use std::collections::{HashMap, VecDeque};
use alloy_dyn_abi::abi::token;
use ethers::abi::Token;
use ethers::prelude::*;
use ethers::utils::keccak256;
use std::sync::Arc;
use eyre::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use ethers::types::transaction::eip712::*;
use ethers::types::transaction::eip2718::TypedTransaction; // for simulation
use ethers::types::*;
use lazy_static::lazy_static;

lazy_static::lazy_static! {
    pub static ref UNISWAP_V3_FACTORY: Address = "0x1F98431c8aD98523631AE4a59f267346ea31F984".parse().unwrap();
    pub static ref USDC_MAINNET_ADDRESS: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".parse().unwrap();
    pub static ref WETH_MAINNET_ADDRESS: Address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".parse().unwrap();
    pub static ref WBTC_MAINNET_ADDRESS: Address = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599".parse().unwrap();
    pub static ref LINK_MAINNET_ADDRESS: Address = "0x514910771AF9Ca656af840dff83E8264EcF986CA".parse().unwrap();
    pub static ref WHITE_MAINNET_ADDRESS: Address = "0x5F0E628B693018f639D10e4A4F59BD4d8B2B6B44".parse().unwrap();



    pub static ref CLIENT: Arc<SignerMiddleware<Provider<Http>, LocalWallet>> = {
        let rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://eth-mainnet.g.alchemy.com/v2/JqGfpyexs472qJw3Tmt02j77PXZ3cQwB".to_string());
        let private_key = "889f48dc8ce8b2b46ec23fa9a793afcb49d4c38b19cf1fbffc0467ee092688f1";
        let provider = Provider::<Http>::try_from(rpc_url).unwrap();
        let wallet = private_key.parse::<LocalWallet>().unwrap().with_chain_id(1u64);
        Arc::new(SignerMiddleware::new(provider, wallet))
    };

    pub static ref V3_FACTORY: IUniswapV3Factory<SignerMiddleware<Provider<Http>, LocalWallet>> = 
       IUniswapV3Factory::new(*UNISWAP_V3_FACTORY, CLIENT.clone());
}

abigen!(
        IUniswapV3Factory,
        r#"[
            function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address) 
        ]"#,
    );

abigen!(
    IUniswapV3Pool,
    r#"[
        function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext, uint8 feeProtocol, bool unlocked)
        function liquidity() external view returns (uint128)
    ]"#,
);

// Return pool address if created, or None if it doesn't exist.
pub async fn get_v3_pool_address<M: Middleware + 'static>(
    client: Arc<M>,
    factory_addr: Address,
    token_a: Address,
    token_b: Address,
    fee: u32,
) -> Result<Option<Address>> {
    let factory = IUniswapV3Factory::new(factory_addr, client);
    let pool = factory
        .get_pool(token_a, token_b, fee as u32)
        .call()
        .await?;
    println!("Pool address: {:#x}", pool);
    Ok(if pool == Address::zero() { None } else { Some(pool) })
}

// Returns true if the pool is initialized
pub async fn is_pool_initialized<M: Middleware + 'static>(
    client: Arc<M>,
    pool_addr: Address,
) -> Result<bool> {
    let pool = IUniswapV3Pool::new(pool_addr, client);
    let (sqrt_price_x96, tick, _, _, _, _, _) = pool.slot_0().call().await?;
    println!("sqrt_price_x96: {}, tick: {}", sqrt_price_x96, tick);
    Ok(sqrt_price_x96 != U256::zero() && tick != 0)
}

// Check if the pool has liquidity
pub async fn has_liquidity<M:Middleware + 'static>(
    client: Arc<M>,
    pool_addr: Address,
) -> Result<bool> {
    let pool = IUniswapV3Pool::new(pool_addr, client);
    let liq = pool.liquidity().call().await?;
    println!("Liquidity: {}", liq);
    Ok(liq > 0)
}

// Create a graph to connect all pools as nodes and edges, creating a graph from a given dictionary of token addresses

struct PoolGraphV3 {
    pub adj_list: HashMap<String, Vec<(String, u32)>>,
}

impl PoolGraphV3 {
    fn new() -> Self {
        Self {
            adj_list: HashMap::new(),
        }
    }

    async fn add_edge_from_dict(&mut self, token_dict: &HashMap<String, Address>, fee_tiers: &[u32],) -> eyre::Result<()> {
        let keys: Vec<_> = token_dict.iter().collect();

        for i in 0..keys.len() {
            let (token1_name, &address1) = keys[i];
            for j in (i+1)..keys.len() {
                let (token2_name, &address2) = keys[j];

                for &fee in fee_tiers {
                    if let Ok(Some(pool_addr)) = get_v3_pool_address(CLIENT.clone(), UNISWAP_V3_FACTORY.clone(), address1, address2, fee).await {
                        // Check if pool is initialized and has liquidity
                        let initialized = is_pool_initialized(CLIENT.clone(), pool_addr).await?;
                        let has_liquidity = has_liquidity(CLIENT.clone(), pool_addr).await?;
                        if initialized && has_liquidity {
                            self.add_edge(token1_name.clone(), token2_name.clone(), fee);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn add_edge(&mut self, token1: String, token2: String, fee: u32) {
        self.adj_list
            .entry(token1.clone())
            .or_insert_with(Vec::new)
            .push((token2.clone(), fee));

        self.adj_list
            .entry(token2)
            .or_insert_with(Vec::new)
            .push((token1.clone(), fee));
    }
}

type Graph = HashMap<String, Vec<(String, u32)>>;

fn find_all_routes(graph: &Graph, token_input: String, token_target: String) -> Vec<Vec<(String, u32)>> {
    let mut routes: Vec<Vec<(String, u32)>> = Vec::new();

    let mut queue: VecDeque<(String, Vec<(String, u32)>)> = VecDeque::new();

    queue.push_back((token_input.to_string(), Vec::new()));

    while let Some((current, path)) = queue.pop_front() {
        if path.len() >= 3 {
            continue;
        }

        if let Some(neighbours) = graph.get(&current) {
            for (next_token, fee) in neighbours {
                if path.iter().any(|(t, _)| t == next_token) || current == *next_token {
                    continue;
                }

                let mut new_path = path.clone();
                new_path.push((next_token.clone(), *fee));

                if *next_token == token_target {
                    routes.push(new_path.clone());
                }
                else {
                    queue.push_back((next_token.clone(), new_path));
                }
            }
        }
    }
    routes
}

// #[tokio::main]
// async fn main() -> Result<()> {
//     if let Some(pool_addr) = get_v3_pool_address(CLIENT.clone(), UNISWAP_V3_FACTORY.clone(), USDC_MAINNET_ADDRESS.clone(), WETH_MAINNET_ADDRESS.clone(), 10000).await? {
//     println!("Pool address: {:#x}", pool_addr); 
//     let initialized = is_pool_initialized(CLIENT.clone(), pool_addr).await?;
//     println!("Initialized? {}", initialized);
// }else{
//     println!("Pool not found");
// }

// Ok(())
// }

// #[tokio::main]
// async fn main() -> eyre::Result<()> {
//     let mut tokens: HashMap<String, Address> = HashMap::from([
//         ("toncoin".to_string(), "0x582d872a1b094fc48f5de31d3b73f2d9be47def1".parse()?),
//         ("solx".to_string(), "0xe0b7ad7f8f26e2b00c8b47b5df370f15f90fcf48".parse()?),
//         ("ldo".to_string(), "0x5a98fcbea516cf06857215779fd812ca3bef1b32".parse()?),
//         ("ondo".to_string(), "0xfaba6f8e4a5e8ab82f62fe7c39859fa577269be3".parse()?),
//         ("trx".to_string(), "0x50327c6c5a14dcade707abad2e27eb517df87ab5".parse()?),
//         ("rsc".to_string(), "0xfbb75a59193a3525a8825bebe7d4b56899e2f7e1".parse()?),
//         ("xor".to_string(), "0x40fd72257597aa14c7231a7b1aaa29fce868f677".parse()?),
//         ("uni".to_string(), "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984".parse()?),
//         ("aave".to_string(), "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9".parse()?),
//         ("cbbtc".to_string(), "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf".parse()?),
//         ("usdc".to_string(), "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".parse()?), 
//         ("weth".to_string(), "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".parse()?),
//         ("link".to_string(), "0x514910771af9ca656af840dff83e8264ecf986ca".parse()?),
//         ("bio".to_string(), "0xcb1592591996765ec0efc1f92599a19767ee5ffa".parse()?),
//         ("ena".to_string(), "0x57e114b691db790c35207b2e685d4a43181e6061".parse()?),
//         ("usdt".to_string(), "0xdac17f958d2ee523a2206206994597c13d831ec7".parse()?),
//         ("wepe".to_string(), "0xccb365d2e11ae4d6d74715c680f56cf58bf4bf10".parse()?),
//         ("wld".to_string(), "0x163f8c2467924be0ae7b5347228cabf260318753".parse()?),
//         ("wbtc".to_string(), "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599".parse()?),
//         ("rekt".to_string(), "0xdd3b11ef34cd511a2da159034a05fcb94d806686".parse()?),
//         ("block".to_string(), "0xcab84bc21f9092167fcfe0ea60f5ce053ab39a1e".parse()?),

//     ]);

//     let mut graph = PoolGraphV3::new();
//     let fee_tiers = vec![100, 500, 3000, 10000];
//     graph.add_edge_from_dict(&tokens, &fee_tiers).await?;

//     println!("Pool Graph: {:?}", graph.adj_list);
//  Ok(())
// }

#[tokio::main]
async fn main() {
    // Initialize the graph directly with all nodes and edges
    let graph: Graph = serde_json::from_str(r#"{
  "uni": [["usdt", 500], ["usdt", 3000], ["wbtc", 3000], ["aave", 3000], ["usdc", 3000], ["usdc", 10000], ["weth", 500], ["weth", 3000], ["weth", 10000], ["link", 3000], ["link", 10000]],
  "bio": [["usdt", 3000], ["weth", 3000], ["weth", 10000]],
  "toncoin": [["usdt", 3000], ["usdt", 10000], ["usdc", 10000], ["weth", 10000]],
  "ondo": [["usdt", 10000], ["usdc", 3000], ["weth", 500], ["weth", 3000], ["weth", 10000]],
  "ena": [["usdt", 3000], ["usdc", 500], ["usdc", 3000], ["usdc", 10000], ["weth", 500], ["weth", 3000], ["weth", 10000]],
  "trx": [["weth", 500]],
  "usdc": [["cbbtc", 500], ["cbbtc", 3000], ["ldo", 10000], ["usdt", 100], ["usdt", 500], ["usdt", 3000], ["usdt", 10000], ["wbtc", 500], ["wbtc", 3000], ["wbtc", 10000], ["uni", 3000], ["uni", 10000], ["aave", 3000], ["toncoin", 10000], ["ondo", 3000], ["ena", 500], ["ena", 3000], ["ena", 10000], ["weth", 100], ["weth", 500], ["weth", 3000], ["weth", 10000], ["xor", 10000], ["link", 3000]],
  "ldo": [["usdt", 3000], ["usdc", 10000], ["weth", 3000], ["weth", 10000]],
  "usdt": [["ldo", 3000], ["bio", 3000], ["wbtc", 100], ["wbtc", 500], ["wbtc", 3000], ["uni", 500], ["uni", 3000], ["aave", 3000], ["toncoin", 3000], ["toncoin", 10000], ["ondo", 10000], ["usdc", 100], ["usdc", 500], ["usdc", 3000], ["usdc", 10000], ["ena", 3000], ["weth", 100], ["weth", 500], ["weth", 3000], ["weth", 10000], ["xor", 10000], ["link", 3000]],
  "link": [["usdt", 3000], ["wbtc", 3000], ["uni", 3000], ["uni", 10000], ["aave", 3000], ["usdc", 3000], ["weth", 500], ["weth", 3000], ["weth", 10000]],
  "cbbtc": [["wbtc", 500], ["usdc", 500], ["usdc", 3000], ["weth", 500], ["weth", 3000]],
  "wepe": [["weth", 3000], ["weth", 10000]],
  "wbtc": [["cbbtc", 500], ["usdt", 100], ["usdt", 500], ["usdt", 3000], ["uni", 3000], ["aave", 3000], ["usdc", 500], ["usdc", 3000], ["usdc", 10000], ["weth", 100], ["weth", 500], ["weth", 3000], ["weth", 10000], ["link", 3000]],
  "solx": [["weth", 3000]],
  "rekt": [["weth", 3000]],
  "wld": [["aave", 10000], ["weth", 10000]],
  "weth": [["trx", 500], ["cbbtc", 500], ["cbbtc", 3000], ["ldo", 3000], ["ldo", 10000], ["usdt", 100], ["usdt", 500], ["usdt", 3000], ["usdt", 10000], ["solx", 3000], ["bio", 3000], ["bio", 10000], ["wbtc", 100], ["wbtc", 500], ["wbtc", 3000], ["wbtc", 10000], ["wepe", 3000], ["wepe", 10000], ["uni", 500], ["uni", 3000], ["uni", 10000], ["aave", 500], ["aave", 3000], ["aave", 10000], ["rekt", 3000], ["toncoin", 10000], ["ondo", 500], ["ondo", 3000], ["ondo", 10000], ["usdc", 100], ["usdc", 500], ["usdc", 3000], ["usdc", 10000], ["ena", 500], ["ena", 3000], ["ena", 10000], ["wld", 10000], ["xor", 3000], ["xor", 10000], ["link", 500], ["link", 3000], ["link", 10000], ["block", 10000]],
  "aave": [["usdt", 3000], ["wbtc", 3000], ["uni", 3000], ["usdc", 3000], ["weth", 500], ["weth", 3000], ["weth", 10000], ["wld", 10000], ["link", 3000]],
  "block": [["weth", 10000]],
  "xor": [["usdt", 10000], ["usdc", 10000], ["weth", 3000], ["weth", 10000]]
}
    "#).unwrap();

    let routes = find_all_routes(&graph, "aave".to_string(), "cbbtc".to_string());

    for (i, route) in routes.iter().enumerate() {
        println!("Route {}: {:?}", i + 1, route);
    }
}




