use std::collections::{HashMap, VecDeque};
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
    pub static ref STATE_VIEW_ADDRESS: Address = "0x7ffe42c4a5deea5b0fec41c94c136cf115597227".parse().unwrap();
    pub static ref USDC_ADDRESS: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".parse().unwrap();
    pub static ref LINK_ADDRESS: Address = "0x514910771AF9Ca656af840dff83E8264EcF986CA".parse().unwrap();
    pub static ref CLIENT: Arc<SignerMiddleware<Provider<Http>, LocalWallet>> = {
        let rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://eth-mainnet.g.alchemy.com/v2/JqGfpyexs472qJw3Tmt02j77PXZ3cQwB".to_string());
        let private_key = "889f48dc8ce8b2b46ec23fa9a793afcb49d4c38b19cf1fbffc0467ee092688f1";
        let provider = Provider::<Http>::try_from(rpc_url).unwrap();
        let wallet = private_key.parse::<LocalWallet>().unwrap().with_chain_id(1u64);
        Arc::new(SignerMiddleware::new(provider, wallet))
    };
    pub static ref STATE_VIEW: IStateView<SignerMiddleware<Provider<Http>, LocalWallet>> =
        IStateView::new(*STATE_VIEW_ADDRESS, CLIENT.clone());
}
abigen!(
    IStateView,
    r#"[
        function getSlot0(bytes32 poolId) external view returns (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee)
        function getTickInfo(bytes32 poolId, int24 tick) external view returns (uint128 liquidityGross, uint128 liquidityNet, uint256 feeGrowthOutside0X128, uint256 feeGrowthOutside1X128)
    ]"#
);

abigen!(
    IPoolManager,
    r#"[
        function getPool(bytes32 poolId) external view returns (address pool)
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
async fn pool_exists(token1: Address, token2: Address, fee: u32) -> eyre::Result<bool> {

    let fee_tier_to_tick_spacing = {
        match fee {
            100 => 1,
            500 => 10,
            3000 => 60,
            10000 => 200,
            // unsupported condition
            _ => return Ok(false),
        }
    };
    // StateView contract deployed alongside PoolManager
    let pool_id = compute_pool_id(token1, token2, fee, fee_tier_to_tick_spacing, Address::zero());
    // Check if the pool exists by querying the state
    println!("Slot0: {:?}", STATE_VIEW.get_slot_0(pool_id).call().await);
    let slot0 = STATE_VIEW.get_slot_0(pool_id).call().await?;

    let (sqrt_price, tick, _, _) = slot0;

    if sqrt_price ==U256::zero() && tick == 0 {
        Ok(false)
    } else {
        Ok(true)
    }
}

struct PoolGraph {
    pub adj_list: HashMap<String, Vec<(String, u32)>>,
}

impl PoolGraph {
    fn new() -> PoolGraph {
        PoolGraph {
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
                    if pool_exists(address1, address2, fee).await? {
                        self.add_edge(token1_name.clone(), token2_name.clone(), fee);
                    }
                }
            }
        }
    Ok(())
    }

    fn add_edge(&mut self, token1: String, token2: String, fee: u32) {
        //  insert token1 -> token2

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

    // queue stores (current_token, path_so_far)
    let mut queue: VecDeque<(String, Vec<(String, u32)>)> = VecDeque::new();

    queue.push_back((token_input.to_string(), Vec::new()));

    while let Some((current, path)) = queue.pop_front() {
        // stop exploring if path length already reached 3
        if path.len() >= 3 {
            continue;
        }

        if let Some(neighbours) = graph.get(&current) {
            for (next_token, fee) in neighbours {
                // avoid cycles by checking if token already exists in path
                if path.iter().any(|(t, _)| t == next_token) || current == *next_token {
                    continue;
                }

                let mut new_path = path.clone();
                new_path.push((next_token.clone(), *fee));

                if *next_token == token_target {
                    // found a complete route
                    routes.push(new_path.clone());
                }
                else{
                    queue.push_back((next_token.clone(), new_path));
                }
            }
        }
    }

    routes

}




// #[tokio::main]
// async fn main() -> eyre::Result<()> {
//     dotenv::dotenv().ok();
//     let rpc_url = std::env::var("ETH_RPC_URL")
//         .unwrap_or_else(|_| "https://rpc.ankr.com/eth_sepolia/e2a1f8575bdf5101891a705f337daa3557709d00237390d9e49b18d346".to_string());
//     let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

//     let provider = Provider::<Http>::try_from(rpc_url)?;
//     let wallet = private_key.parse::<LocalWallet>()?.with_chain_id(11155111u64);
//     let client = Arc::new(SignerMiddleware::new(provider, wallet));

//     // StateView contract deployed alongside PoolManager
//     let state_view_address: Address = "0xe1dd9c3fa50edb962e442f60dfbc432e24537e4c".parse()?;  
//     let state_view = IStateView::new(state_view_address, client.clone());

//     // Tokens
//     let usdc: Address = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238".parse()?;
//     let link: Address = "0x779877A7B0D9E8603169DdbD7836e478b4624789".parse()?;

//     // Compute poolId
//     let pool_id = compute_pool_id(usdc, link, 3000, 60, Address::zero());

//     // Try fetching slot0 (will revert if pool doesn’t exist)
//     let slot0 = state_view.get_slot_0(pool_id).call().await?;

//     println!("Pool slot0: {:?}", slot0);

//     Ok(())
// }

// #[tokio::main]
// async fn main() -> eyre::Result<()> {
//     let mut tokens: HashMap<String, Address> = HashMap::from([
//         ("usdc".to_string(), "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".parse()?),
//         ("link".to_string(), "0x514910771AF9Ca656af840dff83E8264EcF986CA".parse()?),
//         ("wbtc".to_string(), "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599".parse()?),
//         ("white".to_string(), "0x5F0E628B693018f639D10e4A4F59BD4d8B2B6B44".parse()?),
//         ("pepe".to_string(), "0x6982508145454Ce325dDbE47a25d4ec3d2311933".parse()?),
//         ("usdt".to_string(), "0xdAC17F958D2ee523a2206206994597C13D831ec7".parse()?),
//         ("trinity".to_string(), "0xc299004a310303D1C0005Cb14c70ccC02863924d".parse()?),
//         ("dai".to_string(), "0x6B175474E89094C44Da98b954EedeAC495271d0F".parse()?),
//         ("pancakeswap".to_string(), "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82".parse()?),
//         ("usde".to_string(), "0x4c9EDD5852cd905f086C759E8383e09bff1E68B3".parse()?),
//         ("wsteth".to_string(), "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0".parse()?),
//         ("cbbtc".to_string(), "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf".parse()?),
//         ("weeth".to_string(), "0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee".parse()?),
//         ("rlusd".to_string(), "0x8292Bb45bf1Ee4d140127049757C2E0fF06317eD".parse()?),
//         ("eurc".to_string(), "0x1aBaEA1f7C830bD89Acc67eC4af516284b1bC33c".parse()?),
//         ("wm".to_string(), "0x437cc33344a0B27A429f795ff6B469C72698B291".parse()?),
//         ("ena".to_string(), "0x57e114B691Db790C35207b2e685D4A43181e6061".parse()?),
//         ("block".to_string(), "0xCaB84bc21F9092167fCFe0ea60f5CE053ab39a1E".parse()?),
//         ("sei".to_string(), "0xbdF43ecAdC5ceF51B7D1772F722E40596BC1788B".parse()?),
//         ("bio".to_string(), "0xcb1592591996765Ec0eFc1f92599A19767ee5ffA".parse()?),
//         ("uni".to_string(), "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984".parse()?),
//         ("susde".to_string(), "0x9D39A5DE30e57443BfF2A8307A4256c8797A3497".parse()?),
//         ("satoshit".to_string(), "0xACCfD598Ef801178ED6c816C234b16eC51AE9F32".parse()?),
//         ("thbill".to_string(), "0x5FA487BCa6158c64046B2813623e20755091DA0b".parse()?),
//         ("usd1".to_string(), "0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d".parse()?),
//         ("mhrd".to_string(), "0x10EE9F68EE4e4d311e854AE14C53F5B25A917f85".parse()?),
//         ("reth".to_string(), "0xae78736Cd615f374D3085123A210448E74Fc6393".parse()?),
//         ("aave".to_string(), "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9".parse()?),
//         ("ldo".to_string(), "0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32".parse()?),
//         ("paxg".to_string(), "0x45804880De22913dAFE09f4980848ECE6EcbAf78".parse()?),
//         ("syrupusdc".to_string(), "0x80ac24aA929eaF5013f6436cdA2a7ba190f5Cc0b".parse()?),
//         ("spx".to_string(), "0xE0f63A424a4439cBE457D80E4f4b51aD25b2c56C".parse()?),
//         ("ap".to_string(), "0xe60e9BD04ccc0a394f1fDf29874e35a773cb07f4".parse()?),
//         ("tbtc".to_string(), "0x18084fbA666a33d37592fA2633fD49a74DD93a88".parse()?),
//         ("rekt".to_string(), "0xdd3B11eF34cd511a2DA159034a05fcb94D806686".parse()?),
//         ("mog".to_string(), "0xaaeE1A9723aaDB7afA2810263653A34bA2C21C7a".parse()?),
//         ("weth".to_string(), "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".parse()?),
//         ("strat".to_string(), "0x14cF922aa1512Adfc34409b63e18D391e4a86A2f".parse()?),
//         ("trx".to_string(), "0x50327c6c5a14DCaDE707ABad2E27eB517df87AB5".parse()?),
//         ("lbtc".to_string(), "0x8236a87084f8B84306f72007F36F2618A5634494".parse()?),
//         ("floki".to_string(), "0xcf0C122c6b73ff809C693DB761e7BaeBe62b6a2E".parse()?),
//         ("eigen".to_string(), "0xC2C390c6CD3C4e6c2b70727d35a45e8a072F18cA".parse()?),
//         ("fluid".to_string(), "0xc1cd3D0913f4633b43FcdDBCd7342bC9b71C676f".parse()?),
//         ("rch".to_string(), "0x57B96D4aF698605563A4653D882635da59Bf11AF".parse()?),
//     ]);

//     let mut graph = PoolGraph::new();
//     let fee_tiers = vec![100, 500, 3000, 10000];
//     graph.add_edge_from_dict(&tokens, &fee_tiers).await?;

//     println!("Pool Graph: {:?}", graph.adj_list);
//  Ok(())
// }

fn calculate_PI_based_route(path: &PoolGraph) {
    
}





#[tokio::main]
async fn main() {
    // Initialize the graph directly with all nodes and edges
    let graph: Graph = serde_json::from_str(r#"{"aave": [("uni", 3000), ("uni", 10000), ("wbtc", 100), ("wbtc", 500), ("wbtc", 3000), ("pepe", 3000), ("dai", 10000)], "lbtc": [("usdc", 3000)], "usde": [("wbtc", 10000)], "link": [("uni", 3000), ("uni", 10000), ("wbtc", 3000)], "syrupusdc": [("usdc", 500), ("usdc", 3000)], "rlusd": [("pepe", 10000), ("usdc", 500)], "ldo": [("ena", 3000)], "ena": [("trx", 10000), ("ldo", 3000)], "wm": [("usdc", 10000)], "eurc": [("usdt", 100), ("dai", 500), ("usdc", 100), ("usdc", 500), ("usdc", 3000)], "dai": [("uni", 3000), ("paxg", 500), ("wbtc", 3000), ("pepe", 3000), ("eurc", 500), ("tbtc", 500), ("usdc", 100), ("usdc", 500), ("usdc", 10000), ("aave", 10000)], "susde": [("usdt", 100), ("usdt", 500), ("usdc", 100), ("usdc", 500)], "spx": [("mog", 10000)], "uni": [("wbtc", 100), ("wbtc", 3000), ("usdt", 100), ("usdt", 500), ("usdt", 3000), ("dai", 3000), ("usdc", 3000), ("usdc", 10000), ("aave", 3000), ("aave", 10000), ("link", 3000), ("link", 10000)], "usdt": [("trx", 100), ("trx", 3000), ("susde", 100), ("susde", 500), ("uni", 100), ("uni", 500), ("uni", 3000), ("reth", 10000), ("wsteth", 3000), ("block", 10000), ("cbbtc", 100), ("cbbtc", 3000), ("cbbtc", 10000), ("paxg", 100), ("paxg", 3000), ("paxg", 10000), ("wbtc", 100), ("wbtc", 500), ("wbtc", 3000), ("wbtc", 10000), ("pepe", 500), ("pepe", 3000), ("eurc", 100), ("ap", 3000), ("ap", 10000)], "trx": [("usdt", 100), ("usdt", 3000), ("usdc", 100), ("usdc", 500), ("ena", 10000)], "block": [("usd1", 10000), ("usdt", 10000)], "reth": [("usdt", 10000)], "wbtc": [("uni", 100), ("uni", 3000), ("pepe", 100), ("pepe", 10000), ("usdt", 100), ("usdt", 500), ("usdt", 3000), ("usdt", 10000), ("dai", 3000), ("usdc", 100), ("usdc", 500), ("usdc", 3000), ("usdc", 10000), ("aave", 100), ("aave", 500), ("aave", 3000), ("link", 3000), ("usde", 10000)], "wsteth": [("cbbtc", 10000), ("usdt", 3000), ("usdc", 3000), ("usdc", 10000)], "paxg": [("usdt", 100), ("usdt", 3000), ("usdt", 10000), ("dai", 500), ("usdc", 500), ("usdc", 3000)], "usd1": [("block", 10000), ("usdc", 500)], "mog": [("spx", 10000)], "pepe": [("wbtc", 100), ("wbtc", 10000), ("usdt", 500), ("usdt", 3000), ("dai", 3000), ("rlusd", 10000), ("usdc", 100), ("usdc", 3000), ("usdc", 10000), ("aave", 3000)], "cbbtc": [("wsteth", 10000), ("usdt", 100), ("usdt", 3000), ("usdt", 10000)], "tbtc": [("dai", 500), ("usdc", 10000)], "ap": [("usdt", 3000), ("usdt", 10000), ("usdc", 3000)], "usdc": [("trx", 100), ("trx", 500), ("wm", 10000), ("usd1", 500), ("susde", 100), ("susde", 500), ("uni", 3000), ("uni", 10000), ("lbtc", 3000), ("wsteth", 3000), ("wsteth", 10000), ("paxg", 500), ("paxg", 3000), ("wbtc", 100), ("wbtc", 500), ("wbtc", 3000), ("wbtc", 10000), ("pepe", 100), ("pepe", 3000), ("pepe", 10000), ("eurc", 100), ("eurc", 500), ("eurc", 3000), ("tbtc", 10000), ("syrupusdc", 500), ("syrupusdc", 3000), ("dai", 100), ("dai", 500), ("dai", 10000), ("rlusd", 500), ("ap", 3000)]}
    "#).unwrap();

    let routes = find_all_routes(&graph, "aave".to_string(), "paxg".to_string());

    for (i, route) in routes.iter().enumerate() {
        println!("Route {}: {:?}", i + 1, route);
    }
}