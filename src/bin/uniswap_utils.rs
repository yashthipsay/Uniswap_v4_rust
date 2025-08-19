use ethers::abi::Token;
use ethers::prelude::*;
use ethers::utils::keccak256;
use std::sync::Arc;
use eyre::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use ethers::types::transaction::eip712::*;
use ethers::types::transaction::eip2718::TypedTransaction; // for simulation
use ethers::types::*;

abigen!(
    IStateView,
    r#"[
        function getSlot0(bytes32 poolId) external view returns (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee)
        function getTickInfo(bytes32 poolId, int24 tick) external view returns (uint128 liquidityGross, uint128 liquidityNet, uint256 feeGrowthOutside0X128, uint256 feeGrowthOutside1X128)
    ]"#
);

#[derive(Debug)]
pub struct PoolKey{
    pub currency0: Address,
    pub currency1: Address,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: Address,
}

fn compute_pool_id(currency0: Address, currency1: Address, fee: u32, tick_spacing: i32, hooks: Address) -> [u8; 32] {
 let encoded = ethers::abi::encode(&[
    Token::Tuple(vec![
        Token::Address(currency0),
        Token::Address(currency1),
        Token::Uint(fee.into()),
        Token::Int(tick_spacing.into()),
        Token::Address(hooks),
    ])
 ]);
 ethers::utils::keccak256(encoded)
}


#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "https://rpc.ankr.com/eth_sepolia/e2a1f8575bdf5101891a705f337daa3557709d00237390d9e49b18d346".to_string());
    let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

    let provider = Provider::<Http>::try_from(rpc_url)?;
    let wallet = private_key.parse::<LocalWallet>()?.with_chain_id(11155111u64);
    let client = Arc::new(SignerMiddleware::new(provider, wallet));

    // StateView contract deployed alongside PoolManager
    let state_view_address: Address = "0xe1dd9c3fa50edb962e442f60dfbc432e24537e4c".parse()?;  
    let state_view = IStateView::new(state_view_address, client.clone());

    // Tokens
    let usdc: Address = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238".parse()?;
    let link: Address = "0x779877A7B0D9E8603169DdbD7836e478b4624789".parse()?;

    // Compute poolId
    let pool_id = compute_pool_id(usdc, link, 3000, 60, Address::zero());

    // Try fetching slot0 (will revert if pool doesn’t exist)
    let slot0 = state_view.get_slot_0(pool_id).call().await?;

    println!("Pool slot0: {:?}", slot0);

    Ok(())
}
