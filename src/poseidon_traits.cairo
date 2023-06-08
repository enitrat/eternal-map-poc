use traits::Into;
use starknet::ContractAddress;
use poseidon::poseidon_hash_span;
use array::ArrayTrait;

trait PoseidonHash<T> {
    fn hash(state: felt252, value: T) -> felt252;
}

impl PoseidonHashFelt252 of PoseidonHash<felt252> {
    fn hash(state: felt252, value: felt252) -> felt252 {
        let mut arr = ArrayTrait::new();
        arr.append(state);
        arr.append(value);
        poseidon_hash_span(arr.span())
    }
}

impl PoseidonHashBool of PoseidonHash<bool> {
    fn hash(state: felt252, value: bool) -> felt252 {
        PoseidonHash::<felt252>::hash(state, if value {
            1
        } else {
            0
        })
    }
}

impl PoseidonHashU8 of PoseidonHash<u8> {
    fn hash(state: felt252, value: u8) -> felt252 {
        PoseidonHash::<felt252>::hash(state, value.into())
    }
}

impl PoseidonHashU16 of PoseidonHash<u16> {
    fn hash(state: felt252, value: u16) -> felt252 {
        PoseidonHash::<felt252>::hash(state, value.into())
    }
}

impl PoseidonHashU32 of PoseidonHash<u32> {
    fn hash(state: felt252, value: u32) -> felt252 {
        PoseidonHash::<felt252>::hash(state, value.into())
    }
}

impl PoseidonHashU64 of PoseidonHash<u64> {
    fn hash(state: felt252, value: u64) -> felt252 {
        PoseidonHash::<felt252>::hash(state, value.into())
    }
}

impl PoseidonHashU128 of PoseidonHash<u128> {
    fn hash(state: felt252, value: u128) -> felt252 {
        PoseidonHash::<felt252>::hash(state, value.into())
    }
}

impl PoseidonHashU256 of PoseidonHash<u256> {
    fn hash(state: felt252, value: u256) -> felt252 {
        let state = PoseidonHash::<u128>::hash(state, value.low);
        PoseidonHash::<u128>::hash(state, value.high)
    }
}

impl PoseidonHashContractAddress of PoseidonHash<starknet::ContractAddress> {
    fn hash(state: felt252, value: starknet::ContractAddress) -> felt252 {
        PoseidonHash::<felt252>::hash(state, value.into())
    }
}

impl TupleSize0PoseidonHash of PoseidonHash<()> {
    fn hash(state: felt252, value: ()) -> felt252 {
        state
    }
}

impl TupleSize1PoseidonHash<E0, impl E0PoseidonHash: PoseidonHash<E0>> of PoseidonHash<(E0, )> {
    fn hash(state: felt252, value: (E0, )) -> felt252 {
        let (e0, ) = value;
        E0PoseidonHash::hash(state, e0)
    }
}

impl TupleSize2PoseidonHash<
    E0,
    E1,
    impl E0PoseidonHash: PoseidonHash<E0>,
    impl E1PoseidonHash: PoseidonHash<E1>,
    impl E0Drop: Drop<E0>,
    impl E1Drop: Drop<E1>
> of PoseidonHash<(E0, E1)> {
    fn hash(state: felt252, value: (E0, E1, )) -> felt252 {
        let (e0, e1) = value;
        let state = E0PoseidonHash::hash(state, e0);
        E1PoseidonHash::hash(state, e1)
    }
}

impl TupleSize3PoseidonHash<
    E0,
    E1,
    E2,
    impl E0PoseidonHash: PoseidonHash<E0>,
    impl E1PoseidonHash: PoseidonHash<E1>,
    impl E2PoseidonHash: PoseidonHash<E2>,
    impl E0Drop: Drop<E0>,
    impl E1Drop: Drop<E1>,
    impl E2Drop: Drop<E2>,
> of PoseidonHash<(E0, E1, E2)> {
    fn hash(state: felt252, value: (E0, E1, E2)) -> felt252 {
        let (e0, e1, e2) = value;
        let state = E0PoseidonHash::hash(state, e0);
        let state = E1PoseidonHash::hash(state, e1);
        E2PoseidonHash::hash(state, e2)
    }
}

impl TupleSize4PoseidonHash<
    E0,
    E1,
    E2,
    E3,
    impl E0PoseidonHash: PoseidonHash<E0>,
    impl E1PoseidonHash: PoseidonHash<E1>,
    impl E2PoseidonHash: PoseidonHash<E2>,
    impl E3PoseidonHash: PoseidonHash<E3>,
    impl E0Drop: Drop<E0>,
    impl E1Drop: Drop<E1>,
    impl E2Drop: Drop<E2>,
    impl E3Drop: Drop<E3>,
> of PoseidonHash<(E0, E1, E2, E3)> {
    fn hash(state: felt252, value: (E0, E1, E2, E3)) -> felt252 {
        let (e0, e1, e2, e3) = value;
        let state = E0PoseidonHash::hash(state, e0);
        let state = E1PoseidonHash::hash(state, e1);
        let state = E2PoseidonHash::hash(state, e2);
        E3PoseidonHash::hash(state, e3)
    }
}

fn foo(input: Span<u64>) -> starknet::SyscallResult<u256> {
    starknet::syscalls::keccak_syscall(input)
}
