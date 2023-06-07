use starknet::{
    StorageAddress, StorageBaseAddress, SyscallResult, SyscallResultTrait, SyscallResultTraitImpl,
    StorageAccess, storage_access::{storage_base_address_from_felt252, Felt252TryIntoStorageAddress}
};
use traits::{Into, TryInto};
use array::ArrayTrait;
use option::OptionTrait;
use poseidon::poseidon_hash_span;

// Eternal single variable
trait EternalVariableTrait<T> {
    fn address(ref self: felt252) -> StorageBaseAddress;
    fn read(self: felt252) -> T;
    fn write(self: felt252, ref value: felt252);
}

impl EternalStorageAccessImpl<T, impl TStorageAccess: StorageAccess<T>> of EternalVariableTrait<T> {
    fn address(ref self: felt252) -> StorageBaseAddress {
        let address = get_address_from_name(self);
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

    //TODO
    fn write(
        mut self: felt252, ref value: felt252
    ) { // let address: StorageAddress = self.get_address();
    // StorageAccess::write(address, value);
    }
}


// TODO eternal mappings

fn get_address_from_name(variable_name: felt252) -> felt252 {
    let mut data: Array<felt252> = ArrayTrait::new();
    data.append(variable_name);
    let hashed_name: felt252 = poseidon_hash_span(data.span());
    let MASK_250: u256 = 0x03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    // By taking the 250 least significant bits of the hash output, we get a valid 250bits storage address.
    let result: felt252 = (hashed_name.into() & MASK_250).try_into().unwrap();
    result
}
