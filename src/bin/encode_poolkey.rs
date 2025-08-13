use std::str::FromStr;
use alloy::dyn_abi::DynSolValue;
use alloy_primitives::{keccak256, Address, I256, U256};
use alloy_primitives::aliases::{U24, I24};

fn main() {
    // Inputs
    let raw0 = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
    let raw1 = "0x779877A7B0D9E8603169DdbD7836e478b4624789";
    let fee: u32 = 3000;          // uint24
    let tick_spacing: i32 = 60;   // int24
    let hooks = Address::ZERO;

    // convert to 24-bit aliases
    let fee_u24 = U24::try_from(fee).expect("bad fee");
    let tick_i24 = I24::try_from(tick_spacing).expect("bad tick spacing");

    let a0 = Address::from_str(raw0).unwrap();
    let a1 = Address::from_str(raw1).unwrap();

    // Sort currencies
    let (c0, c1) = if a0 < a1 { (a0, a1) } else { (a1, a0) };

    // Encode PoolKey (address,address,uint24,int24,address)
    let encoded = DynSolValue::Tuple(vec![
        DynSolValue::Address(c0),
        DynSolValue::Address(c1),
        DynSolValue::Uint(U256::from(fee_u24), 24),
        DynSolValue::Int(I256::from(tick_i24), 24),
        DynSolValue::Address(hooks),
    ])
    .abi_encode();

    // Compute poolId
    let pool_id = keccak256(encoded);

    println!("PoolId: 0x{}", hex::encode(pool_id));

    // Build full calldata for getLiquidity(bytes32)
    let selector = &keccak256("hasPool(bytes32)".as_bytes())[0..4];
    let full_data = [selector, pool_id.as_slice()].concat();
    println!("Full data: 0x{}", hex::encode(full_data));
}
