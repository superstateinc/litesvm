use {
    litesvm::LiteSVM,
    litesvm_persistence::{from_bytes, load_from_file, save_to_file, to_bytes},
    solana_account::Account,
    solana_address::Address,
    solana_clock::Clock,
    solana_instruction::{account_meta::AccountMeta, Instruction},
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signer::Signer,
    solana_system_interface::instruction::transfer,
    solana_transaction::{versioned::VersionedTransaction, Transaction},
};

fn temp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("litesvm_persistence_tests");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[test]
fn basic_account_round_trip() {
    let mut svm = LiteSVM::new();
    let address = Address::new_unique();
    svm.set_account(
        address,
        Account {
            lamports: 1_000_000,
            data: vec![1, 2, 3, 4, 5],
            owner: Address::new_unique(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let path = temp_path("basic_account.bin");
    save_to_file(&svm, &path).unwrap();
    let restored = load_from_file(&path).unwrap();

    let original = svm.get_account(&address).unwrap();
    let restored_account = restored.get_account(&address).unwrap();
    assert_eq!(original.lamports, restored_account.lamports);
    assert_eq!(original.data, restored_account.data);
    assert_eq!(original.owner, restored_account.owner);
}

#[test]
fn multiple_accounts_round_trip() {
    let mut svm = LiteSVM::new();
    let mut addresses = Vec::new();
    for i in 0u64..10 {
        let address = Address::new_unique();
        addresses.push(address);
        svm.set_account(
            address,
            Account {
                lamports: (i + 1) * 1_000,
                data: vec![i as u8; ((i + 1) * 10) as usize],
                owner: Address::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }

    let path = temp_path("multiple_accounts.bin");
    save_to_file(&svm, &path).unwrap();
    let restored = load_from_file(&path).unwrap();

    for (i, address) in addresses.iter().enumerate() {
        let original = svm.get_account(address).unwrap();
        let restored_account = restored.get_account(address).unwrap();
        assert_eq!(original.lamports, restored_account.lamports, "account {i} lamports mismatch");
        assert_eq!(original.data, restored_account.data, "account {i} data mismatch");
        assert_eq!(original.owner, restored_account.owner, "account {i} owner mismatch");
    }
}

#[test]
fn sysvar_round_trip() {
    let mut svm = LiteSVM::new();

    // Set a custom clock
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 1_700_000_000;
    clock.slot = 42;
    clock.epoch = 7;
    svm.set_sysvar(&clock);

    let path = temp_path("sysvar.bin");
    save_to_file(&svm, &path).unwrap();
    let restored = load_from_file(&path).unwrap();

    let restored_clock = restored.get_sysvar::<Clock>();
    assert_eq!(restored_clock.unix_timestamp, 1_700_000_000);
    assert_eq!(restored_clock.slot, 42);
    assert_eq!(restored_clock.epoch, 7);
}

#[test]
fn config_round_trip() {
    let svm = LiteSVM::new()
        .with_sigverify(false)
        .with_blockhash_check(false)
        .with_log_bytes_limit(Some(50_000));

    let path = temp_path("config.bin");
    save_to_file(&svm, &path).unwrap();
    let restored = load_from_file(&path).unwrap();

    assert_eq!(restored.get_sigverify(), false);
    assert_eq!(restored.get_blockhash_check(), false);
    assert_eq!(restored.get_log_bytes_limit(), Some(50_000));
}

#[test]
fn blockhash_round_trip() {
    let mut svm = LiteSVM::new();
    // Expire the blockhash a few times to get a non-genesis hash
    svm.expire_blockhash();
    svm.expire_blockhash();
    let original_hash = svm.latest_blockhash();

    let path = temp_path("blockhash.bin");
    save_to_file(&svm, &path).unwrap();
    let restored = load_from_file(&path).unwrap();

    assert_eq!(restored.latest_blockhash(), original_hash);
}

#[test]
fn airdrop_keypair_round_trip() {
    let svm = LiteSVM::new();
    let original_pubkey = svm.airdrop_pubkey();

    let path = temp_path("airdrop_kp.bin");
    save_to_file(&svm, &path).unwrap();
    let restored = load_from_file(&path).unwrap();

    assert_eq!(restored.airdrop_pubkey(), original_pubkey);
}

#[test]
fn transaction_history_round_trip() {
    let mut svm = LiteSVM::new()
        .with_sigverify(false)
        .with_blockhash_check(false);

    let from_kp = Keypair::new();
    let from = from_kp.pubkey();
    let to = Address::new_unique();

    svm.airdrop(&from, 10_000_000).unwrap();
    let ix = transfer(&from, &to, 1000);
    let tx = Transaction::new(
        &[&from_kp],
        Message::new(&[ix], Some(&from)),
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx).unwrap();
    let sig = result.signature;

    // Verify the transaction is in history before save
    assert!(svm.get_transaction(&sig).is_some());

    let path = temp_path("history.bin");
    save_to_file(&svm, &path).unwrap();
    let restored = load_from_file(&path).unwrap();

    // Verify the transaction is still in history after load
    let restored_tx = restored.get_transaction(&sig);
    assert!(restored_tx.is_some(), "transaction not found in restored history");
}

#[test]
fn bytes_round_trip() {
    let mut svm = LiteSVM::new();
    let address = Address::new_unique();
    svm.set_account(
        address,
        Account {
            lamports: 42,
            data: vec![0xDE, 0xAD],
            owner: Address::new_unique(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let bytes = to_bytes(&svm).unwrap();
    let restored = from_bytes(&bytes).unwrap();

    let original = svm.get_account(&address).unwrap();
    let restored_account = restored.get_account(&address).unwrap();
    assert_eq!(original.lamports, restored_account.lamports);
    assert_eq!(original.data, restored_account.data);
}

#[test]
fn airdrop_works_after_restore() {
    let svm = LiteSVM::new();
    let path = temp_path("airdrop_after_restore.bin");
    save_to_file(&svm, &path).unwrap();
    let mut restored = load_from_file(&path).unwrap();

    // Airdrop should work on the restored instance since the keypair is preserved
    let recipient = Address::new_unique();
    restored.airdrop(&recipient, 5_000).unwrap();
    let account = restored.get_account(&recipient).unwrap();
    assert_eq!(account.lamports, 5_000);
}

#[test]
fn send_transaction_after_restore() {
    let mut svm = LiteSVM::new()
        .with_sigverify(false)
        .with_blockhash_check(false);

    let from_kp = Keypair::new();
    let from = from_kp.pubkey();
    let to = Address::new_unique();
    svm.airdrop(&from, 10_000_000).unwrap();

    let path = temp_path("send_after_restore.bin");
    save_to_file(&svm, &path).unwrap();
    let mut restored = load_from_file(&path).unwrap();

    // Send a transaction on the restored instance
    let ix = transfer(&from, &to, 1000);
    let tx = Transaction::new(
        &[&from_kp],
        Message::new(&[ix], Some(&from)),
        restored.latest_blockhash(),
    );
    restored.send_transaction(tx).unwrap();

    let to_account = restored.get_account(&to).unwrap();
    assert_eq!(to_account.lamports, 1000);
}

#[test]
fn bpf_program_round_trip() {
    let program_id = Address::new_unique();
    let mut svm = LiteSVM::new();
    let program_bytes =
        include_bytes!("../../node-litesvm/program_bytes/spl_example_logging.so");
    svm.add_program(program_id, program_bytes).unwrap();

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    // Execute the program before save to confirm it works
    let ix = Instruction {
        program_id,
        accounts: vec![AccountMeta {
            pubkey: Address::new_unique(),
            is_signer: false,
            is_writable: true,
        }],
        data: vec![5, 10, 11, 12, 13, 14],
    };
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[ix.clone()], Some(&payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[&payer]).unwrap();
    let meta = svm.send_transaction(tx).unwrap();
    assert_eq!(meta.logs[1], "Program log: static string");

    // Save and restore
    let path = temp_path("bpf_program.bin");
    save_to_file(&svm, &path).unwrap();
    let mut restored = load_from_file(&path).unwrap();

    // Execute the same program on the restored instance
    let payer2 = Keypair::new();
    restored.airdrop(&payer2.pubkey(), 1_000_000_000).unwrap();
    let blockhash2 = restored.latest_blockhash();
    let ix2 = Instruction {
        program_id,
        accounts: vec![AccountMeta {
            pubkey: Address::new_unique(),
            is_signer: false,
            is_writable: true,
        }],
        data: vec![5, 10, 11, 12, 13, 14],
    };
    let msg2 = Message::new_with_blockhash(&[ix2], Some(&payer2.pubkey()), &blockhash2);
    let tx2 = VersionedTransaction::try_new(VersionedMessage::Legacy(msg2), &[&payer2]).unwrap();
    let meta2 = restored.send_transaction(tx2).unwrap();

    // The restored program should produce identical logs
    assert_eq!(meta2.logs[1], "Program log: static string");
}

#[test]
fn load_nonexistent_file_returns_error() {
    let result = load_from_file("/tmp/litesvm_nonexistent_file_12345.bin");
    assert!(result.is_err());
}

#[test]
fn load_corrupted_data_returns_error() {
    let path = temp_path("corrupted.bin");
    std::fs::write(&path, b"this is not valid bincode data").unwrap();
    let result = load_from_file(&path);
    assert!(result.is_err());
}
