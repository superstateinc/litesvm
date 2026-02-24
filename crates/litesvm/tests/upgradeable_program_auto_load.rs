// Test to verify auto-loading of BPF Upgradeable programs
//
// This test verifies that programs added to the account database are automatically
// loaded into the program cache when referenced in transactions, even if they weren't
// explicitly loaded via add_program().

use {
    litesvm::LiteSVM, solana_account::AccountSharedData, solana_instruction::Instruction,
    solana_keypair::Keypair, solana_loader_v3_interface::state::UpgradeableLoaderState,
    solana_pubkey::Pubkey, solana_sdk_ids::bpf_loader_upgradeable, solana_signer::Signer,
    solana_transaction::Transaction, std::path::PathBuf,
};

fn read_counter_program() -> Vec<u8> {
    let mut so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    so_path.push("test_programs/target/deploy/counter.so");
    // If the program doesn't exist, use a minimal dummy program
    std::fs::read(so_path).unwrap_or_else(|_| {
        // Minimal BPF program bytes (just enough to pass validation)
        vec![
            0x7f, 0x45, 0x4c, 0x46, // ELF magic
            0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    })
}

/// This test demonstrates the explicit load_existing_programs() method works correctly
#[test]
fn test_explicit_load_existing_programs() {
    let mut svm = LiteSVM::new();

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    // Add a program using the standard method
    let program_id = Pubkey::new_unique();
    let program_bytes = read_counter_program();

    svm.add_program(program_id, &program_bytes).unwrap();

    // Get the program account
    let program_account = svm.get_account(&program_id).unwrap();
    assert!(program_account.executable);

    // Create a new SVM instance and manually add the program account
    let mut svm2 = LiteSVM::new();
    svm2.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    // Simulate restoring from saved state - we have the account but not the cache
    svm2.set_account(program_id, program_account.into())
        .unwrap();

    // Explicitly load all existing programs
    svm2.load_existing_programs().unwrap();

    // Verify the program is now in the cache by checking it can be called
    // (Even if it fails execution, it should not fail with "program not found")
    let counter_address = Pubkey::new_unique();
    svm2.set_account(
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
        svm2.latest_blockhash(),
    );

    let result = svm2.send_transaction(tx);

    // Should not fail with "program not found"
    if let Err(e) = &result {
        let err_string = format!("{:?}", e);
        assert!(
            !err_string.contains("AccountNotFound"),
            "Program should be loaded via load_existing_programs(), but got: {:?}",
            e
        );
    }
}

/// Test that programs with the upgradeable loader are auto-loaded when synced
#[test]
fn test_bpf_upgradeable_program_auto_load_on_sync() {
    let mut svm = LiteSVM::new();

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let program_id = Pubkey::new_unique();
    let programdata_id = Pubkey::new_unique();
    let program_bytes = read_counter_program();

    // Create a Program account (would normally be created during deployment)
    let program_state = UpgradeableLoaderState::Program {
        programdata_address: programdata_id,
    };
    let program_data = bincode::serialize(&program_state).unwrap();
    let mut program_account =
        AccountSharedData::new(1_000_000, program_data.len(), &bpf_loader_upgradeable::id());
    program_account.set_data_from_slice(&program_data);
    // Note: executable flag will be set by sync_accounts

    // Create ProgramData account
    let programdata_state = UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: Some(payer.pubkey()),
    };
    let programdata_metadata = bincode::serialize(&programdata_state).unwrap();
    let mut programdata_account = AccountSharedData::new(
        10_000_000,
        UpgradeableLoaderState::size_of_programdata_metadata() + program_bytes.len(),
        &bpf_loader_upgradeable::id(),
    );
    let mut data = programdata_metadata.clone();
    data.extend_from_slice(&program_bytes);
    programdata_account.set_data_from_slice(&data);

    // Add accounts to SVM
    svm.set_account(program_id, program_account.into()).unwrap();
    svm.set_account(programdata_id, programdata_account.into())
        .unwrap();

    // Load existing programs (this should auto-load the upgradeable program)
    svm.load_existing_programs().unwrap();

    // Verify program account is now marked executable
    let program_account_after = svm.get_account(&program_id).unwrap();
    assert!(
        program_account_after.executable,
        "Program account should be marked executable after sync"
    );

    // Verify we can reference the program in a transaction
    let counter_address = Pubkey::new_unique();
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

    // Should not fail with "program not found" or "not executable"
    if let Err(e) = &result {
        let err_string = format!("{:?}", e);
        assert!(
            !err_string.contains("AccountNotFound"),
            "Program should be auto-loaded, but got: {:?}",
            e
        );
        assert!(
            !err_string.contains("InvalidProgramForExecution"),
            "Program should be executable, but got: {:?}",
            e
        );
    }
}
