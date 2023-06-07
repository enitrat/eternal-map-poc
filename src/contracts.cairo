use traits::{Into, TryInto};
use option::OptionTrait;

use starknet::{
    SyscallResult, syscalls::{storage_read_syscall, storage_write_syscall},
    contract_address::{ContractAddress, Felt252TryIntoContractAddress, ContractAddressIntoFelt252},
    class_hash::{ClassHash, Felt252TryIntoClassHash, ClassHashIntoFelt252}
};
use serde::Serde;

#[contract]
mod EternalStorage {
    use starknet::{StorageAddress, StorageAccess, StorageBaseAddress, storage_address_from_base};
    use starknet::{
        SyscallResult, syscalls::{storage_read_syscall, storage_write_syscall},
        contract_address::{
            ContractAddress, Felt252TryIntoContractAddress, ContractAddressIntoFelt252
        },
        class_hash::{ClassHash, Felt252TryIntoClassHash, ClassHashIntoFelt252}
    };
    use array::ArrayTrait;
    use array::SpanTrait;
    use option::OptionTrait;
    use traits::{Into, TryInto};
    use poseidon::poseidon_hash_span;
    use starknet::storage_access::Felt252TryIntoStorageAddress;
    use map_poc::eternal_variable::{EternalVariableTrait};


    struct Storage {
        total_users: u128,
        balances: LegacyMap<ContractAddress, u128>
    }

    fn test() {
        total_users::read();
    }

    const FELT_SLOT: felt252 = 'felt_slot';
    const U256_SLOT: felt252 = 'u256_slot';

    #[view]
    fn read_felt_slot() -> felt252 {
        EternalVariableTrait::<felt252>::read(FELT_SLOT)
    }

    #[view]
    fn read_u256_slot() -> u256 {
        EternalVariableTrait::<u256>::read(U256_SLOT)
    }
}
