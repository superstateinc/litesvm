// Test to verify auto-loading of BPF Upgradeable programs
//
// This test verifies that programs added to the account database are automatically
// loaded into the program cache when referenced in transactions, even if they weren't
// explicitly loaded via add_program().

use {
    agave_feature_set::FeatureSet,
    litesvm::LiteSVM,
    solana_address::Address,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_loader_v3_interface::{
        instruction as loader_v3_instruction, state::UpgradeableLoaderState,
    },
    solana_native_token::LAMPORTS_PER_SOL,
    solana_sdk_ids::bpf_loader_upgradeable,
    solana_signer::Signer,
    solana_transaction::Transaction,
    std::path::PathBuf,
};

fn read_counter_program() -> Vec<u8> {
    let mut so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    so_path.push("test_programs/target/deploy/counter.so");
    std::fs::read(so_path).unwrap_or_else(|_| {
        include_bytes!("../../loader/tests/programs_bytes/hello_world.so").to_vec()
    })
}

fn new_v3_deploy_svm() -> LiteSVM {
    LiteSVM::default()
        .with_feature_set(FeatureSet::all_enabled())
        .with_builtins()
        .with_lamports(1_000_000u64.wrapping_mul(LAMPORTS_PER_SOL))
        .with_sysvars()
}

fn deploy_upgradeable_program(svm: &mut LiteSVM, payer: &Keypair, program_bytes: &[u8]) -> Address {
    const CHUNK_SIZE: usize = 512;

    let buffer = Keypair::new();
    let program = Keypair::new();
    let payer_address = payer.pubkey();

    let buffer_len = UpgradeableLoaderState::size_of_buffer(program_bytes.len());
    let buffer_lamports = svm.minimum_balance_for_rent_exemption(buffer_len);
    let create_buffer_tx = Transaction::new_signed_with_payer(
        &loader_v3_instruction::create_buffer(
            &payer_address,
            &buffer.pubkey(),
            &payer_address,
            buffer_lamports,
            program_bytes.len(),
        )
        .unwrap(),
        Some(&payer_address),
        &[payer, &buffer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(create_buffer_tx).unwrap();

    for (chunk_idx, chunk) in program_bytes.chunks(CHUNK_SIZE).enumerate() {
        let write_tx = Transaction::new_signed_with_payer(
            &[loader_v3_instruction::write(
                &buffer.pubkey(),
                &payer_address,
                (chunk_idx * CHUNK_SIZE) as u32,
                chunk.to_vec(),
            )],
            Some(&payer_address),
            &[payer],
            svm.latest_blockhash(),
        );
        svm.send_transaction(write_tx).unwrap();
    }

    let program_account_rent =
        svm.minimum_balance_for_rent_exemption(UpgradeableLoaderState::size_of_program());
    let programdata_rent = svm.minimum_balance_for_rent_exemption(
        UpgradeableLoaderState::size_of_programdata(program_bytes.len() * 2),
    );
    #[allow(deprecated)]
    let deploy_tx = Transaction::new_signed_with_payer(
        &loader_v3_instruction::deploy_with_max_program_len(
            &payer_address,
            &program.pubkey(),
            &buffer.pubkey(),
            &payer_address,
            program_account_rent + programdata_rent,
            program_bytes.len() * 2,
        )
        .unwrap(),
        Some(&payer_address),
        &[payer, &program],
        svm.latest_blockhash(),
    );
    svm.send_transaction(deploy_tx).unwrap();

    program.pubkey()
}

/// This test demonstrates the explicit load_existing_programs() method works correctly
#[test]
fn test_explicit_load_existing_programs() {
    let mut svm = LiteSVM::default()
        .with_feature_set(FeatureSet::all_enabled())
        .with_builtins()
        .with_lamports(1_000_000u64.wrapping_mul(LAMPORTS_PER_SOL))
        .with_sysvars();

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let program_id = Address::new_unique();
    let programdata_id = Address::new_unique();
    let program_bytes = read_counter_program();

    let program_state = UpgradeableLoaderState::Program {
        programdata_address: programdata_id,
    };
    let program_data = bincode::serialize(&program_state).unwrap();
    let mut program_account =
        solana_account::Account::new(1_000_000, program_data.len(), &bpf_loader_upgradeable::id());
    program_account.data = program_data;
    program_account.executable = true;

    let programdata_state = UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: Some(payer.pubkey()),
    };
    let mut programdata_data = bincode::serialize(&programdata_state).unwrap();
    programdata_data.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
    programdata_data.extend_from_slice(&program_bytes);
    let mut programdata_account = solana_account::Account::new(
        10_000_000,
        programdata_data.len(),
        &bpf_loader_upgradeable::id(),
    );
    programdata_account.data = programdata_data;

    svm.set_account(programdata_id, programdata_account)
        .unwrap();
    svm.set_account(program_id, program_account).unwrap();

    svm.load_existing_programs().unwrap();

    let counter_address = Address::new_unique();
    svm.set_account(
        counter_address,
        solana_account::Account {
            lamports: 5,
            data: vec![0_u8; std::mem::size_of::<u32>()],
            owner: program_id,
            ..Default::default()
        },
    )
    .unwrap();

    let instruction = Instruction {
        program_id,
        accounts: vec![solana_instruction::AccountMeta::new(counter_address, false)],
        data: vec![0, 1],
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);

    if let Err(e) = &result {
        let err_string = format!("{:?}", e);
        assert!(
            !err_string.contains("AccountNotFound"),
            "Program should be loaded via load_existing_programs(), but got: {:?}",
            e
        );
        assert!(
            !err_string.contains("InvalidProgramForExecution"),
            "Program should be executable after load_existing_programs(), but got: {:?}",
            e
        );
    }
}

/// Test that BPF loader accounts are synced even when not in the writable set.
#[test]
fn test_bpf_loader_accounts_synced() {
    let mut svm = new_v3_deploy_svm();

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    let program_id = deploy_upgradeable_program(&mut svm, &payer, &read_counter_program());

    let stored = svm.get_account(&program_id).unwrap();
    assert!(stored.executable);
    assert_eq!(stored.owner, bpf_loader_upgradeable::id());

    let counter_address = Address::new_unique();
    svm.set_account(
        counter_address,
        solana_account::Account {
            lamports: 5,
            data: vec![0_u8; std::mem::size_of::<u32>()],
            owner: program_id,
            ..Default::default()
        }
        .into(),
    )
    .unwrap();

    let instruction = Instruction {
        program_id,
        accounts: vec![solana_instruction::AccountMeta::new(counter_address, false)],
        data: vec![0, 1],
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);

    if let Err(e) = &result {
        let err_string = format!("{:?}", e);
        assert!(
            !err_string.contains("AccountNotFound"),
            "Program should be synced after deploy, but got: {:?}",
            e
        );
        assert!(
            !err_string.contains("InvalidProgramForExecution"),
            "Program should be synced and executable after deploy, but got: {:?}",
            e
        );
    }
}
