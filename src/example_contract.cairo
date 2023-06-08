use traits::{Into, TryInto};
use option::OptionTrait;

use starknet::{
    SyscallResult, syscalls::{storage_read_syscall, storage_write_syscall},
    contract_address::{ContractAddress, Felt252TryIntoContractAddress, ContractAddressIntoFelt252},
    class_hash::{ClassHash, Felt252TryIntoClassHash, ClassHashIntoFelt252}
};
use serde::Serde;


#[abi]
trait IEternalStorage {
    fn read_felt_slot() -> felt252;
    fn write_felt_slot(value: felt252);
    fn read_u256_slot() -> u256;
    fn write_u256_slot(value: u256);
    fn read_single_mapping(key: felt252) -> felt252;
    fn write_single_mapping(key: felt252, value: felt252);
    fn read_double_mapping(keys: (felt252, felt252)) -> u256;
    fn write_double_mapping(keys: (felt252, felt252), value: u256);
}

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
    use starknet::storage_access::Felt252TryIntoStorageAddress;
    use eternal_poc::eternal_variable::{EternalVariableTrait, EternalMappingTrait};


    struct Storage {
        total_users: u128,
        balances: LegacyMap<ContractAddress, u128>
    }

    fn test() {
        total_users::read();
    }

    const FELT_SLOT: felt252 = 'felt_slot';
    const U256_SLOT: felt252 = 'u256_slot';
    const SINGLE_MAPPING: felt252 = 'single_mapping';
    const DOUBLE_MAPPING: felt252 = 'double_mapping';

    #[view]
    fn read_felt_slot() -> felt252 {
        EternalVariableTrait::<felt252>::read(FELT_SLOT)
    }

    #[external]
    fn write_felt_slot(value: felt252) {
        EternalVariableTrait::<felt252>::write(FELT_SLOT, value);
    }

    #[view]
    fn read_u256_slot() -> u256 {
        EternalVariableTrait::<u256>::read(U256_SLOT)
    }

    #[external]
    fn write_u256_slot(value: u256) {
        EternalVariableTrait::<u256>::write(U256_SLOT, value);
    }

    #[view]
    fn read_single_mapping(key: felt252) -> felt252 {
        EternalMappingTrait::<felt252, felt252>::read(SINGLE_MAPPING, key)
    }

    #[external]
    fn write_single_mapping(key: felt252, value: felt252) {
        EternalMappingTrait::<felt252, felt252>::write(SINGLE_MAPPING, key, value);
    }

    #[view]
    fn read_double_mapping(keys: (felt252, felt252)) -> u256 {
        EternalMappingTrait::<u256, (felt252, felt252)>::read(DOUBLE_MAPPING, keys)
    }

    #[view]
    fn write_double_mapping(keys: (felt252, felt252), value: u256) {
        EternalMappingTrait::<u256, (felt252, felt252)>::write(DOUBLE_MAPPING, keys, value)
    }
}


#[cfg(test)]
mod tests {
    use super::{IEternalStorageDispatcher, IEternalStorageDispatcherTrait};
    use super::EternalStorage;
    use debug::PrintTrait;
    use starknet::deploy_syscall;
    use option::OptionTrait;
    use array::ArrayTrait;
    use traits::{Into, TryInto};
    use starknet::class_hash::Felt252TryIntoClassHash;
    use result::ResultTrait;

    #[test]
    #[available_gas(2000000000)]
    fn test_read_write_single_var() {
        // Set up.
        let mut calldata: Array<felt252> = ArrayTrait::new();
        let (address0, _) = deploy_syscall(
            EternalStorage::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false
        )
            .unwrap();
        let mut contract = IEternalStorageDispatcher { contract_address: address0 };

        // Write to felt slot.
        let felt_value: felt252 = 42;
        contract.write_felt_slot(felt_value);

        // Read from slot.
        let read_value = contract.read_felt_slot();
        assert(read_value == felt_value, 'wrong value read');

        // Write to u256 slot.
        let u256_value: u256 = u256 { low: 1, high: 1 };
        contract.write_u256_slot(u256_value);

        // Read from slot.
        let read_u256_value = contract.read_u256_slot();
        assert(read_u256_value == u256_value, 'wrong value read');
    }


    #[test]
    #[available_gas(2000000000)]
    fn test_read_write_mapping_var() {
        // Set up.
        let mut calldata: Array<felt252> = ArrayTrait::new();
        let (address0, _) = deploy_syscall(
            EternalStorage::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false
        )
            .unwrap();
        let mut contract = IEternalStorageDispatcher { contract_address: address0 };

        // Write to felt slot.
        let key_1: felt252 = 'key_1';
        let value_1: felt252 = 100;
        contract.write_single_mapping(key_1, value_1);

        // Read from slot.
        let read_key_1 = contract.read_single_mapping(key_1);
        assert(read_key_1 == value_1, 'wrong value read');

        // Write to u256 slot.
        let u256_value: u256 = u256 { low: 1, high: 1 };
        contract.write_u256_slot(u256_value);

        // Read from slot.
        let read_u256_value = contract.read_u256_slot();
        assert(read_u256_value == u256_value, 'wrong value read');
    }

    #[test]
    #[available_gas(2000000000)]
    fn test_read_write_double_mapping_var() {
        // Set up.
        let mut calldata: Array<felt252> = ArrayTrait::new();
        let (address0, _) = deploy_syscall(
            EternalStorage::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false
        )
            .unwrap();
        let mut contract = IEternalStorageDispatcher { contract_address: address0 };

        // Write to felt slot.
        let key_1: felt252 = 'key_1';
        let key_2: felt252 = 'key_2';
        let value_1: u256 = u256 { low: 1, high: 1 };
        contract.write_double_mapping((key_1, key_2), value_1);

        // Read from slot.
        let read_value = contract.read_double_mapping((key_1, key_2));
        assert(read_value == value_1, 'wrong value read');

        // Write to u256 slot.
        let u256_value: u256 = u256 { low: 1, high: 1 };
        contract.write_u256_slot(u256_value);

        // Read from slot.
        let read_u256_value = contract.read_u256_slot();
        assert(read_u256_value == u256_value, 'wrong value read');
    }

    #[test]
    #[available_gas(2000000000)]
    #[should_panic]
    fn test_write_read_wrong_key_should_fail() {
        // Set up.
        let mut calldata: Array<felt252> = ArrayTrait::new();
        let (address0, _) = deploy_syscall(
            EternalStorage::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false
        )
            .unwrap();
        let mut contract = IEternalStorageDispatcher { contract_address: address0 };

        // Write to felt slot.
        let key_1: felt252 = 'key_1';
        let key_2: felt252 = 'key_2';
        let value_1: u256 = u256 { low: 1, high: 1 };
        contract.write_double_mapping((key_1, key_2), value_1);

        // Read from slot.
        let wrong_key_2: felt252 = 'wrong_key_2';
        let read_value = contract.read_double_mapping((key_1, wrong_key_2));
        assert(read_value == value_1, 'wrong value read');
    }
}
