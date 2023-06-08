use starknet::{
    StorageAddress, StorageBaseAddress, SyscallResult, SyscallResultTrait, SyscallResultTraitImpl,
    StorageAccess, storage_access::{storage_base_address_from_felt252, Felt252TryIntoStorageAddress}
};
use traits::{Into, TryInto};
use array::ArrayTrait;
use option::OptionTrait;
use poseidon::poseidon_hash_span;
use eternal_poc::poseidon_traits::PoseidonHash;

// Eternal single variable
trait EternalVariableTrait<T> {
    fn address(ref self: felt252) -> StorageBaseAddress;
    fn read(self: felt252) -> T;
    fn write(self: felt252, value: T);
}

impl EternalStorageAccessImpl<
    T, impl TStorageAccess: StorageAccess<T>, impl TDrop: Drop<T>
> of EternalVariableTrait<T> {
    fn address(ref self: felt252) -> StorageBaseAddress {
        let address = get_address_of_variable(self);
        storage_base_address_from_felt252(address)
    }

    fn read(mut self: felt252) -> T {
        // Only address_domain 0 is currently supported.
        let address_domain = 0_u32;

        let value = starknet::StorageAccess::<T>::read(
            address_domain, EternalVariableTrait::<T>::address(ref self), 
        )
            .unwrap_syscall();
        value
    }

    fn write(mut self: felt252, value: T) {
        let address_domain = 0_u32;
        starknet::StorageAccess::<T>::write(
            address_domain, EternalVariableTrait::<T>::address(ref self), value
        )
            .unwrap_syscall();
    }
}

fn get_address_of_variable(variable_name: felt252) -> felt252 {
    let mut data: Array<felt252> = ArrayTrait::new();
    data.append(variable_name);
    let hashed_name: felt252 = poseidon_hash_span(data.span());
    let MASK_250: u256 = 0x03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    // By taking the 250 least significant bits of the hash output, we get a valid 250bits storage address.
    let result: felt252 = (hashed_name.into() & MASK_250).try_into().unwrap();
    result
}


// Eternal mapping variable
trait EternalMappingTrait<T, U> {
    fn address(ref self: felt252, keys: U) -> StorageBaseAddress;
    fn read(self: felt252, keys: U) -> T;
    fn write(self: felt252, keys: U, value: T);
}

impl EternalMappingImpl<
    T,
    impl TStorageAccess: StorageAccess<T>,
    impl TDrop: Drop<T>,
    U,
    impl UDrop: Drop<U>,
    impl UPoseidonHash: PoseidonHash<U>
> of EternalMappingTrait<T, U> {
    fn address(ref self: felt252, keys: U) -> StorageBaseAddress {
        let address = get_address_of_mapping(self, keys);
        storage_base_address_from_felt252(address)
    }

    fn read(mut self: felt252, keys: U) -> T {
        // Only address_domain 0 is currently supported.
        let address_domain = 0_u32;

        let value = starknet::StorageAccess::<T>::read(
            address_domain, EternalMappingTrait::<T>::address(ref self, keys), 
        )
            .unwrap_syscall();
        value
    }

    fn write(mut self: felt252, keys: U, value: T) {
        let address_domain = 0_u32;
        starknet::StorageAccess::<T>::write(
            address_domain, EternalMappingTrait::<T>::address(ref self, keys), value
        )
            .unwrap_syscall();
    }
}

// TODO eternal mappings

fn get_address_of_mapping<U, impl UPoseidonHash: PoseidonHash<U>, impl UDrop: Drop<U>>(
    variable_name: felt252, keys: U
) -> felt252 {
    let mut data: Array<felt252> = ArrayTrait::new();
    let hash_252: felt252 = PoseidonHash::<U>::hash(variable_name, keys);
    let MASK_250: u256 = 0x03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    // By taking the 250 least significant bits of the hash output, we get a valid 250bits storage address.
    let hash_250: felt252 = (hash_252.into() & MASK_250).try_into().unwrap();
    hash_250
}
