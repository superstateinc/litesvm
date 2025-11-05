use {
    crate::error::{InvalidSysvarDataError, LiteSVMError},
    log::error,
    solana_account::{state_traits::StateMut, AccountSharedData, ReadableAccount, WritableAccount},
    solana_address_lookup_table_interface::{error::AddressLookupError, state::AddressLookupTable},
    solana_clock::Clock,
    solana_instruction::error::InstructionError,
    solana_loader_v3_interface::state::UpgradeableLoaderState,
    solana_message::{
        v0::{LoadedAddresses, MessageAddressTableLookup},
        AddressLoader, AddressLoaderError,
    },
    solana_nonce as nonce,
    solana_program_runtime::{
        loaded_programs::{LoadProgramMetrics, ProgramCacheEntry, ProgramCacheForTxBatch},
        sysvar_cache::SysvarCache,
    },
    solana_pubkey::Pubkey,
    solana_sdk_ids::{
        bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, native_loader,
        sysvar::{
            clock::ID as CLOCK_ID, epoch_rewards::ID as EPOCH_REWARDS_ID,
            epoch_schedule::ID as EPOCH_SCHEDULE_ID, last_restart_slot::ID as LAST_RESTART_SLOT_ID,
            rent::ID as RENT_ID, slot_hashes::ID as SLOT_HASHES_ID,
            stake_history::ID as STAKE_HISTORY_ID,
        },
    },
    solana_system_program::{get_system_account_kind, SystemAccountKind},
    solana_sysvar::Sysvar,
    solana_transaction_error::TransactionError,
    std::{collections::HashMap, sync::Arc},
};

const FEES_ID: Pubkey = solana_pubkey::pubkey!("SysvarFees111111111111111111111111111111111");
const RECENT_BLOCKHASHES_ID: Pubkey =
    solana_pubkey::pubkey!("SysvarRecentB1ockHashes11111111111111111111");

fn handle_sysvar<T>(
    cache: &mut SysvarCache,
    err_variant: InvalidSysvarDataError,
    account: &AccountSharedData,
    mut accounts_clone: HashMap<Pubkey, AccountSharedData>,
    address: Pubkey,
) -> Result<(), InvalidSysvarDataError>
where
    T: Sysvar,
{
    accounts_clone.insert(address, account.clone());
    cache.reset();
    cache.fill_missing_entries(|pubkey, set_sysvar| {
        if let Some(acc) = accounts_clone.get(pubkey) {
            set_sysvar(acc.data())
        }
    });
    let _parsed: T = bincode::deserialize(account.data()).map_err(|_| err_variant)?;
    Ok(())
}

#[derive(Clone, Default)]
pub(crate) struct AccountsDb {
    inner: HashMap<Pubkey, AccountSharedData>,
    pub(crate) programs_cache: ProgramCacheForTxBatch,
    pub(crate) sysvar_cache: SysvarCache,
}

impl AccountsDb {
    pub(crate) fn get_account(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        self.inner.get(pubkey).map(|acc| acc.to_owned())
    }

    /// We should only use this when we know we're not touching any executable or sysvar accounts,
    /// or have already handled such cases.
    pub(crate) fn add_account_no_checks(&mut self, pubkey: Pubkey, account: AccountSharedData) {
        self.inner.insert(pubkey, account);
    }

    pub(crate) fn add_account(
        &mut self,
        pubkey: Pubkey,
        account: AccountSharedData,
    ) -> Result<(), LiteSVMError> {
        if account.executable()
            && pubkey != Pubkey::default()
            && account.owner() != &native_loader::ID
        {
            let loaded_program = self.load_program(&account).map_err(LiteSVMError::Instruction)?;
            self.programs_cache
                .replenish(pubkey, Arc::new(loaded_program));
        } else {
            self.maybe_handle_sysvar_account(pubkey, &account)
                .map_err(LiteSVMError::InvalidSysvarData)?;
        }
        self.add_account_no_checks(pubkey, account);
        Ok(())
    }

    fn maybe_handle_sysvar_account(
        &mut self,
        pubkey: Pubkey,
        account: &AccountSharedData,
    ) -> Result<(), InvalidSysvarDataError> {
        use InvalidSysvarDataError::{
            EpochRewards, EpochSchedule, Fees, LastRestartSlot, RecentBlockhashes, Rent,
            SlotHashes, StakeHistory,
        };

        let cache = &mut self.sysvar_cache;
        #[allow(deprecated)]
        match pubkey {
            CLOCK_ID => {
                let parsed: Clock = bincode::deserialize(account.data())
                    .map_err(|_| InvalidSysvarDataError::Clock)?;
                self.programs_cache.set_slot_for_tests(parsed.slot);
                let mut accounts_clone = self.inner.clone();
                accounts_clone.insert(pubkey, account.clone());
                cache.reset();
                cache.fill_missing_entries(|pubkey, set_sysvar| {
                    if let Some(acc) = accounts_clone.get(pubkey) {
                        set_sysvar(acc.data())
                    }
                });
            }
            EPOCH_REWARDS_ID => {
                handle_sysvar::<solana_epoch_rewards::EpochRewards>(
                    cache,
                    EpochRewards,
                    account,
                    self.inner.clone(),
                    pubkey,
                )?;
            }
            EPOCH_SCHEDULE_ID => {
                handle_sysvar::<solana_epoch_schedule::EpochSchedule>(
                    cache,
                    EpochSchedule,
                    account,
                    self.inner.clone(),
                    pubkey,
                )?;
            }
            FEES_ID => {
                handle_sysvar::<solana_sysvar::fees::Fees>(
                    cache,
                    Fees,
                    account,
                    self.inner.clone(),
                    pubkey,
                )?;
            }
            LAST_RESTART_SLOT_ID => {
                handle_sysvar::<solana_sysvar::last_restart_slot::LastRestartSlot>(
                    cache,
                    LastRestartSlot,
                    account,
                    self.inner.clone(),
                    pubkey,
                )?;
            }
            RECENT_BLOCKHASHES_ID => {
                handle_sysvar::<solana_sysvar::recent_blockhashes::RecentBlockhashes>(
                    cache,
                    RecentBlockhashes,
                    account,
                    self.inner.clone(),
                    pubkey,
                )?;
            }
            RENT_ID => {
                handle_sysvar::<solana_rent::Rent>(
                    cache,
                    Rent,
                    account,
                    self.inner.clone(),
                    pubkey,
                )?;
            }
            SLOT_HASHES_ID => {
                handle_sysvar::<solana_slot_hashes::SlotHashes>(
                    cache,
                    SlotHashes,
                    account,
                    self.inner.clone(),
                    pubkey,
                )?;
            }
            STAKE_HISTORY_ID => {
                handle_sysvar::<solana_sysvar::stake_history::StakeHistory>(
                    cache,
                    StakeHistory,
                    account,
                    self.inner.clone(),
                    pubkey,
                )?;
            }
            _ => {}
        };
        Ok(())
    }

    /// Skip the executable() checks for builtin accounts
    pub(crate) fn add_builtin_account(&mut self, pubkey: Pubkey, data: AccountSharedData) {
        self.inner.insert(pubkey, data);
    }

    pub(crate) fn sync_accounts(
        &mut self,
        mut accounts: Vec<(Pubkey, AccountSharedData)>,
    ) -> Result<(), LiteSVMError> {
        eprintln!("[SYNC_ACCOUNTS] Syncing {} accounts", accounts.len());
        // need to add programdata accounts first if there are any
        itertools::partition(&mut accounts, |x| {
            x.1.owner() == &bpf_loader_upgradeable::id()
                && x.1.data().first().is_some_and(|byte| *byte == 3)
        });

        for (pubkey, mut acc) in accounts {
            eprintln!("[SYNC_ACCOUNTS] Adding account {}: executable={}, owner={}",
                     pubkey, acc.executable(), acc.owner());

            // For BPF Loader Upgradeable V3 program accounts, the executable flag may not be set
            // during deployment. We need to check if this is a Program account and manually set executable=true
            if acc.owner() == &bpf_loader_upgradeable::id() && !acc.executable() {
                eprintln!("[SYNC_ACCOUNTS] Found BPF upgradeable account {}, checking state...", pubkey);
                match acc.state() {
                    Ok(UpgradeableLoaderState::Program { .. }) => {
                        eprintln!("[SYNC_ACCOUNTS] ✓ Detected V3 PROGRAM account {}, setting executable=true", pubkey);
                        acc.set_executable(true);
                    }
                    Ok(UpgradeableLoaderState::ProgramData { .. }) => {
                        eprintln!("[SYNC_ACCOUNTS]   Account {} is ProgramData (not Program), skipping", pubkey);
                    }
                    Ok(state) => {
                        eprintln!("[SYNC_ACCOUNTS]   Account {} has other state: {:?}", pubkey, state);
                    }
                    Err(e) => {
                        eprintln!("[SYNC_ACCOUNTS]   Failed to deserialize state for {}: {:?}", pubkey, e);
                    }
                }
            }

            self.add_account(pubkey, acc)?;
        }

        eprintln!("[SYNC_ACCOUNTS] Checking for programs to auto-load...");
        // After syncing accounts, check for any executable program accounts that weren't explicitly synced
        // This handles the case where deployment creates program+programdata, but only programdata is in ExecutionRecord
        // Also handles BPF Loader V2 programs (Orca/Raydium) loaded via add_program_from_file
        let accounts_snapshot: Vec<(Pubkey, AccountSharedData)> = self.inner.iter()
            .filter(|(pubkey, acc)| {
                let is_executable = acc.executable();
                let is_loadable_program = acc.owner() == &bpf_loader_upgradeable::id()
                    || acc.owner() == &bpf_loader::id();
                let in_cache = self.programs_cache.find(pubkey).is_some();
                let should_load = is_executable && is_loadable_program && !in_cache;
                if should_load {
                    eprintln!("[SYNC_ACCOUNTS]   Found program to auto-load: {}", pubkey);
                }
                should_load
            })
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        eprintln!("[SYNC_ACCOUNTS] Auto-loading {} programs", accounts_snapshot.len());
        for (program_pubkey, program_acc) in accounts_snapshot {
            match self.load_program(&program_acc) {
                Ok(loaded_program) => {
                    eprintln!("[SYNC_ACCOUNTS] Successfully auto-loaded program {}", program_pubkey);
                    self.programs_cache.replenish(program_pubkey, Arc::new(loaded_program));
                }
                Err(e) => {
                    eprintln!("[SYNC_ACCOUNTS] Failed to auto-load program {}: {:?}", program_pubkey, e);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn load_program(
        &self,
        program_account: &AccountSharedData,
    ) -> Result<ProgramCacheEntry, InstructionError> {
        let metrics = &mut LoadProgramMetrics::default();

        let owner = program_account.owner();
        let program_runtime_v1 = self.programs_cache.environments.program_runtime_v1.clone();
        let slot = self.sysvar_cache.get_clock().unwrap().slot;

        if bpf_loader::check_id(owner) | bpf_loader_deprecated::check_id(owner) {
            ProgramCacheEntry::new(
                owner,
                program_runtime_v1,
                slot,
                slot,
                program_account.data(),
                program_account.data().len(),
                &mut LoadProgramMetrics::default(),
            )
            .map_err(|e| {
                error!("Failed to load program: {e:?}");
                InstructionError::InvalidAccountData
            })
        } else if bpf_loader_upgradeable::check_id(owner) {
            let Ok(UpgradeableLoaderState::Program {
                programdata_address,
            }) = program_account.state()
            else {
                error!(
                    "Program account data does not deserialize to UpgradeableLoaderState::Program"
                );
                return Err(InstructionError::InvalidAccountData);
            };
            let programdata_account = self.get_account(&programdata_address).ok_or_else(|| {
                error!("Program data account {programdata_address} not found");
                InstructionError::MissingAccount
            })?;
            let program_data = programdata_account.data();
            if let Some(programdata) =
                program_data.get(UpgradeableLoaderState::size_of_programdata_metadata()..)
            {
                ProgramCacheEntry::new(
                    owner,
                    program_runtime_v1,
                    slot,
                    slot,
                    programdata,
                    program_account
                        .data()
                        .len()
                        .saturating_add(program_data.len()),
                    metrics).map_err(|e| {
                        error!("Error encountered when calling ProgramCacheEntry::new() for bpf_loader_upgradeable: {e:?}");
                        InstructionError::InvalidAccountData
                    })
            } else {
                error!("Index out of bounds using bpf_loader_upgradeable.");
                Err(InstructionError::InvalidAccountData)
            }
        } else {
            error!("Owner does not match any expected loader.");
            Err(InstructionError::IncorrectProgramId)
        }
    }

    /// Load all existing executable programs into the program cache.
    /// This should be called during initialization to ensure programs that exist in the
    /// account database (e.g., from previous test runs) are available for execution.
    pub(crate) fn load_all_existing_programs(&mut self) -> Result<(), LiteSVMError> {
        eprintln!("[LOAD_ALL_EXISTING_PROGRAMS] Scanning for executable programs...");

        let accounts_snapshot: Vec<(Pubkey, AccountSharedData)> = self.inner.iter()
            .filter(|(pubkey, acc)| {
                let is_executable = acc.executable();
                let is_loadable_program = acc.owner() == &bpf_loader_upgradeable::id()
                    || acc.owner() == &bpf_loader::id();
                let in_cache = self.programs_cache.find(pubkey).is_some();
                let should_load = is_executable && is_loadable_program && !in_cache;
                if should_load {
                    eprintln!("[LOAD_ALL_EXISTING_PROGRAMS] Found program to load: {} (owner: {})", pubkey, acc.owner());
                }
                should_load
            })
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        eprintln!("[LOAD_ALL_EXISTING_PROGRAMS] Loading {} programs into cache", accounts_snapshot.len());

        for (program_pubkey, program_acc) in accounts_snapshot {
            match self.load_program(&program_acc) {
                Ok(loaded_program) => {
                    eprintln!("[LOAD_ALL_EXISTING_PROGRAMS] ✓ Successfully loaded program {}", program_pubkey);
                    self.programs_cache.replenish(program_pubkey, Arc::new(loaded_program));
                }
                Err(e) => {
                    eprintln!("[LOAD_ALL_EXISTING_PROGRAMS] ✗ Failed to load program {}: {:?}", program_pubkey, e);
                }
            }
        }

        eprintln!("[LOAD_ALL_EXISTING_PROGRAMS] Completed loading programs");
        Ok(())
    }

    fn load_lookup_table_addresses(
        &self,
        address_table_lookup: &MessageAddressTableLookup,
    ) -> std::result::Result<LoadedAddresses, AddressLookupError> {
        let table_account = self
            .get_account(&address_table_lookup.account_key)
            .ok_or(AddressLookupError::LookupTableAccountNotFound)?;

        if table_account.owner() == &solana_sdk_ids::address_lookup_table::id() {
            let slot_hashes = self.sysvar_cache.get_slot_hashes().unwrap();
            let current_slot = self.sysvar_cache.get_clock().unwrap().slot;
            let lookup_table = AddressLookupTable::deserialize(table_account.data())
                .map_err(|_ix_err| AddressLookupError::InvalidAccountData)?;

            Ok(LoadedAddresses {
                writable: lookup_table.lookup(
                    current_slot,
                    &address_table_lookup.writable_indexes,
                    &slot_hashes,
                )?,
                readonly: lookup_table.lookup(
                    current_slot,
                    &address_table_lookup.readonly_indexes,
                    &slot_hashes,
                )?,
            })
        } else {
            Err(AddressLookupError::InvalidAccountOwner)
        }
    }

    pub(crate) fn withdraw(
        &mut self,
        pubkey: &Pubkey,
        lamports: u64,
    ) -> solana_transaction_error::TransactionResult<()> {
        match self.inner.get_mut(pubkey) {
            Some(account) => {
                let min_balance = match get_system_account_kind(account) {
                    Some(SystemAccountKind::Nonce) => self
                        .sysvar_cache
                        .get_rent()
                        .unwrap()
                        .minimum_balance(nonce::state::State::size()),
                    _ => 0,
                };

                lamports
                    .checked_add(min_balance)
                    .filter(|required_balance| *required_balance <= account.lamports())
                    .ok_or(TransactionError::InsufficientFundsForFee)?;
                account
                    .checked_sub_lamports(lamports)
                    .map_err(|_| TransactionError::InsufficientFundsForFee)?;

                Ok(())
            }
            None => {
                error!("Account {pubkey} not found when trying to withdraw fee.");
                Err(TransactionError::AccountNotFound)
            }
        }
    }
}

fn into_address_loader_error(err: AddressLookupError) -> AddressLoaderError {
    match err {
        AddressLookupError::LookupTableAccountNotFound => {
            AddressLoaderError::LookupTableAccountNotFound
        }
        AddressLookupError::InvalidAccountOwner => AddressLoaderError::InvalidAccountOwner,
        AddressLookupError::InvalidAccountData => AddressLoaderError::InvalidAccountData,
        AddressLookupError::InvalidLookupIndex => AddressLoaderError::InvalidLookupIndex,
    }
}

impl AddressLoader for &AccountsDb {
    fn load_addresses(
        self,
        lookups: &[MessageAddressTableLookup],
    ) -> Result<LoadedAddresses, AddressLoaderError> {
        lookups
            .iter()
            .map(|lookup| {
                self.load_lookup_table_addresses(lookup)
                    .map_err(into_address_loader_error)
            })
            .collect()
    }
}
