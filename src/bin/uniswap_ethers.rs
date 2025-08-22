use ethers::abi::Token;
use ethers::prelude::*;
use ethers::utils::keccak256;
use std::sync::Arc;
use eyre::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use ethers::types::transaction::eip712::*;
use ethers::types::transaction::eip2718::TypedTransaction; // for simulation
use ethers::types::*;
// Contract addresses
const UNIVERSAL_ROUTER_V4: &str = "0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b";
const PERMIT2_CONTRACT: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const STATE_VIEW: &str = "0xE1Dd9c3fA50EDB962E442f60DfBc432e24537E4C";
const USDC: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const LINK: &str = "0x779877A7B0D9E8603169DdbD7836e478b4624789";

// Define Universal Router ABI
abigen!(
    UniversalRouter,
    r#"[
        function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline) external payable
    ]"#,
);

// Define Permit2 ABI (remove struct declarations to avoid name/type collisions)
abigen!(
    Permit2,
    r#"[
        function allowance(address owner, address token, address spender) external view returns (uint160 amount, uint48 expiration, uint48 nonce)
    ]"#,
);

// Define StateView ABI
abigen!(
    StateView,
    r#"[
        function getSlot0(bytes32 poolId) external view returns (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex, uint16 observationCardinality)
        function getLiquidity(bytes32 poolId) external view returns (uint128 liquidity)
    ]"#,
);

// Minimal ERC20 decimals interface
abigen!(
    ERC20Dec,
    r#"[
        function decimals() external view returns (uint8)
    ]"#,
);

// Local EIP-712 structs (avoid collision with abigen output)
#[derive(Clone, Debug, ethers::contract::EthAbiType, ethers::contract::EthAbiCodec)]
struct PermitDetails {
    token: H160,
    amount: U256,      // will truncate to uint160 in EIP712 type string
    expiration: u64,   // uint48
    nonce: u64,        // uint48
}

/// Builds a Permit2 PermitSingle typed-data and signs it with `wallet`.
/// Returns the 65-byte signature r||s||v (with v as 27/28), and the exact fields used.
pub async fn sign_permit2_permit_single(
    wallet: &LocalWallet,
    chain_id: u64,
    permit2: Address,
    token: Address,
    amount_u256: U256,         // will be masked to uint160
    expiration_u64: u64,       // will be masked to uint48
    nonce_u64: u64,            // will be masked to uint48
    spender: Address,
    sig_deadline_u256: U256,   // MUST equal what you pass in calldata
) -> Result<(Vec<u8>, (Address, U256, U256, U256), Address, U256)> {

    // Enforce width constraints exactly as Solidity expects.
    let amount = amount_u256 & ((U256::one() << 160) - 1);
    let expiration = U256::from(expiration_u64) & ((U256::one() << 48) - 1);
    let nonce = U256::from(nonce_u64) & ((U256::one() << 48) - 1);
    let sig_deadline = sig_deadline_u256; // no width restriction (uint256)

    // EIP-712 types & domain (matching Permit2)
    // NOTE: Permit2 uses name "Permit2". Including version "1" is correct for the canonical implementation.
    let domain = serde_json::json!({
        "name": "Permit2",
        // "version": "1",
        "chainId": chain_id,
        "verifyingContract": format!("{:#x}", permit2),
    });

    let types = serde_json::json!({
        "PermitSingle": [
            {"name":"details","type":"PermitDetails"},
            {"name":"spender","type":"address"},
            {"name":"sigDeadline","type":"uint256"}
        ],
        "PermitDetails": [
            {"name":"token","type":"address"},
            {"name":"amount","type":"uint160"},
            {"name":"expiration","type":"uint48"},
            {"name":"nonce","type":"uint48"}
        ]
    });

    let message = serde_json::json!({
        "details": {
            "token": format!("{:#x}", token),
            "amount": amount.to_string(),         // fits into 160 bits
            "expiration": expiration.as_u64(),  // fits into 48 bits
            "nonce": nonce.as_u64(),            // fits into 48 bits
        },
        "spender": format!("{:#x}", spender),
        "sigDeadline": sig_deadline,           // uint256
    });

    let typed = TypedData {
        types: serde_json::from_value(types)?,
        domain: serde_json::from_value(domain)?,
        primary_type: "PermitSingle".to_string(),
        message: serde_json::from_value(message)?,
    };

    let sig = wallet.sign_typed_data(&typed).await?;
    let mut bytes = Vec::with_capacity(65);
    // Convert r and s into 32-byte big-endian arrays
    let mut r_bytes = [0u8; 32];
    sig.r.to_big_endian(&mut r_bytes);
    bytes.extend_from_slice(&r_bytes);
    let mut s_bytes = [0u8; 32];
    sig.s.to_big_endian(&mut s_bytes);
    bytes.extend_from_slice(&s_bytes);
    // ensure v is 27/28 as expected by Permit2
    let v = if sig.v >= 27 { sig.v } else { sig.v + 27 };
    bytes.push(v as u8);

    Ok((bytes, (token, amount, expiration, nonce), spender, sig_deadline))
}

/// Input ABI: ((address,uint160,uint48,uint48),address,uint256) permit, bytes signature
pub fn encode_permit2_permit_input(
    details: (Address, U256, U256, U256), // (token, amount160, expiration48, nonce48)
    spender: Address,
    sig_deadline: U256,
    signature_65: &[u8],
) -> Bytes {
    let permit_tuple = Token::Tuple(vec![
        Token::Tuple(vec![
            Token::Address(details.0),
            Token::Uint(details.1), // amount (uint160 in Solidity, but encoded in 32 bytes)
            Token::Uint(details.2), // expiration (uint48)
            Token::Uint(details.3), // nonce (uint48)
        ]),
        Token::Address(spender),
        Token::Uint(sig_deadline),
    ]);

    let encoded = abi::encode(&[permit_tuple, Token::Bytes(signature_65.to_vec())]);
    Bytes::from(encoded)
}

pub fn build_permit2_digest_dynamic(
    token: Address,
    amount: U256,
    expiration: u64,
    nonce: u64,
    spender: Address,
    sig_deadline: U256,
    chain_id: u64,
    verifying_contract: Address,
) -> [u8; 32] {
    let details = PermitDetails {
        token,
        amount,
        expiration,
        nonce,
    };

    let permit = PermitSingle {
        details,
        spender,
        sig_deadline,
    };

    // Build dynamic domain
    let domain = EIP712Domain {
        name: Some("Permit2".to_string()),
        version: None,
        chain_id: Some(U256::from(11155111u64)),
        verifying_contract: Some(verifying_contract),
        salt: None,
    };

    // Manually compute the EIP-712 digest using the provided domain
    let domain_separator = domain.separator();
    let struct_hash = permit.struct_hash().expect("Failed to compute struct hash");
    let mut digest_input = [0u8; 2 + 32 + 32];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    digest_input[2..34].copy_from_slice(&domain_separator);
    digest_input[34..66].copy_from_slice(&struct_hash);
    keccak256(&digest_input)
}

#[derive(Clone, Debug, ethers::contract::EthAbiType, ethers::contract::EthAbiCodec)]
struct PermitSingle {
    details: PermitDetails,
    spender: H160,
    sig_deadline: U256, // uint256
}

impl Eip712 for PermitSingle {
    type Error = Eip712Error;

    fn domain(&self) -> std::result::Result<EIP712Domain, Self::Error> {
        Ok(EIP712Domain {
            name: Some("Permit2".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(U256::from(11155111u64)),
            verifying_contract: Some(PERMIT2_CONTRACT.parse::<H160>().expect("static address")),
            salt: None,
        })
    }

    fn type_hash() -> std::result::Result<[u8; 32], Self::Error> {
        Ok(keccak256(
            b"PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)",
        ))
    }

    fn struct_hash(&self) -> std::result::Result<[u8; 32], Self::Error> {
        let details_type_hash =
            keccak256(b"PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
        let details_hash = keccak256(ethers::abi::encode(&[
            Token::FixedBytes(details_type_hash.to_vec()),
            Token::Address(self.details.token),
            Token::Uint(self.details.amount),
            Token::Uint(U256::from(self.details.expiration)),
            Token::Uint(U256::from(self.details.nonce)),
        ]));

        let permit_type_hash =
            keccak256(b"PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)");

        let full_hash = keccak256(ethers::abi::encode(&[
            Token::FixedBytes(permit_type_hash.to_vec()),
            Token::FixedBytes(details_hash.to_vec()),
            Token::Address(self.spender),
            Token::Uint(self.sig_deadline),
        ]));

        Ok(full_hash)
    }
}

// Fetch spot price and current tick
async fn get_spot_price<M: Middleware + 'static>(
    client: Arc<M>,
    token0: H160,
    token1: H160,
    fee: u32,
    tick_spacing: i32,
    hooks: H160,
) -> Result<(f64, i32)> {
    let state_view = StateView::new(STATE_VIEW.parse::<H160>()?, client.clone());
    let pool_id = keccak256(ethers::abi::encode(&[Token::Tuple(vec![
        Token::Address(token0),
        Token::Address(token1),
        Token::Uint(U256::from(fee)),
        Token::Int(U256::from(tick_spacing)),
        Token::Address(hooks),
    ])]));
    let (sqrt_price_x96, tick, _obs_idx, _obs_card) = state_view.get_slot_0(pool_id.into()).call().await?;

    // Fetch decimals
    let dec0 = if token0 == H160::zero() { 18 } else { ERC20Dec::new(token0, client.clone()).decimals().call().await.unwrap_or(18) } as i32;
    let dec1 = if token1 == H160::zero() { 18 } else { ERC20Dec::new(token1, client.clone()).decimals().call().await.unwrap_or(18) } as i32;

    let ratio = (sqrt_price_x96.as_u128() as f64 / 2f64.powi(96)).powi(2);
    // Adjust for decimals difference (price = token1 per token0 in their native units)
    let price = ratio * 10f64.powi(dec1 - dec0);

    Ok(if token0 < token1 { (price, tick) } else { (1.0 / price, tick) })
}

// Decode revert reason
fn decode_revert_reason(data: &[u8]) -> Option<String> {
    if data.len() >= 4 && &data[0..4] == [0x08, 0xc3, 0x79, 0xa0] {
        if data.len() >= 4 + 64 {
            let str_len = U256::from_big_endian(&data[36..68]).as_usize();
            let start = 68;
            let end = start + str_len;
            if data.len() >= end {
                return Some(String::from_utf8_lossy(&data[start..end]).into());
            }
        }
    }
    None
}

// Simulate transaction with revert decoding
async fn simulate_with_revert_decoding<M: Middleware>(
    client: Arc<M>,
    tx: TransactionRequest,
) -> Result<Bytes> {
    let typed_tx: TypedTransaction = tx.clone().into();
    match client.call(&typed_tx, None).await {
        Ok(data) => Ok(data),
        Err(e) => {
            if let Some(jsonrpc_err) = e.as_error_response() {
                if let Some(data) = &jsonrpc_err.data {
                    if let Ok(hex_data) = serde_json::from_value::<String>(data.clone()) {
                        if let Ok(revert_data) = hex::decode(hex_data.strip_prefix("0x").unwrap_or(&hex_data)) {
                            if let Some(reason) = decode_revert_reason(&revert_data) {
                                return Err(eyre::eyre!("Revert reason: {}", reason));
                            } else if revert_data.len() >= 4 {
                                let selector = hex::encode(&revert_data[0..4]);
                                let error_map = [
                                    ("0x9860a0a9", "PoolNotInitialized"),
                                    ("0x7c0b7d22", "V4TooLittleReceived"),
                                    ("0x9d5e7b97", "V4TooMuchRequested"),
                                    ("0x4a4f6a7d", "PoolLocked"),
                                    ("0x1b9263bb", "InvalidDelta"),
                                    ("0x5d1d0f9f", "InputLengthMismatch"),
                                    ("0x8baa579f", "InvalidSignature"),
                                    ("0x5b0d3c3d", "InvalidNonce"),
                                    ("0x3a0a5c7b", "ExpiredPermit"),
                                    ("0x5c5a9f0e", "InvalidSigner"),
                                    ("0x0c49ccbe", "ExcessiveInvalidation"),
                                    ("0x3b99b53d", "SwapOutOfBoundsError"),
                                ];
                                for (sel, name) in error_map.iter() {
                                    if &selector == sel {
                                        return Err(eyre::eyre!("Custom error: {}", name));
                                    }
                                }
                                return Err(eyre::eyre!("Unknown error selector: 0x{}", selector));
                            }
                        }
                    }
                }
            }
            Err(eyre::eyre!("Simulation failed: {}", e))
        }
    }
}

fn print_revert_hex_from_error(err: &eyre::Report) {
    let s = format!("{}", err);
    if let Some(start) = s.find("0x") {
        let hex_str = s[start..].split_whitespace().next().unwrap_or("");
        if let Ok(bytes) = hex::decode(hex_str.trim_start_matches("0x")) {
            if bytes.len() >= 4 {
                println!("Decoded revert selector: 0x{}", hex::encode(&bytes[0..4]));
            }
            if bytes.len() >= 36 {
                let arg = U256::from_big_endian(&bytes[4..36]);
                println!("Decoded first uint256 arg: {}", arg);
            } else {
                println!("Revert payload length: {}", bytes.len());
            }
        } else {
            println!("Failed to hex-decode revert string: {}", hex_str);
        }
    } else {
        println!("No hex data found in error string: {}", s);
    }
}

fn _get_all_token_addresses(){

}

fn _map_routes_for_liquidity_pools(){

}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "https://rpc.ankr.com/eth_sepolia/e2a1f8575bdf5101891a705f337daa3557709da7ff9d00237390d9e49b18d346".to_string());
    let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

    let provider = Provider::<Http>::try_from(rpc_url)?;
    let wallet = private_key.parse::<LocalWallet>()?.with_chain_id(11155111u64);
    let client = Arc::new(SignerMiddleware::new(provider, wallet));

    // Swap params
    let amount_to_move = U256::from(2_000_000u128); // 2 USDC (6 decimals)
    let fee = 3000u32;
    let tick_spacing = 60i32;
    let hooks = H160::zero();
    
    // Set dynamic deadlines (current timestamp + 30 minutes)
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let deadline = U256::from(current_timestamp + 30 * 60); // 30 minutes from now
    
    let zero_for_one = USDC.parse::<H160>()? < LINK.parse::<H160>()?;
    let (currency0, currency1) = if zero_for_one {
        (USDC.parse::<H160>()?, LINK.parse::<H160>()?)
    } else {
        (LINK.parse::<H160>()?, USDC.parse::<H160>()?)
    };
    println!("Currency0: {:?}, Currency1: {:?}, ZeroForOne: {}", currency0, currency1, zero_for_one);

    // Liquidity check
    let state_view = StateView::new(STATE_VIEW.parse::<H160>()?, client.clone());
    let pool_id = keccak256(ethers::abi::encode(&[Token::Tuple(vec![
        Token::Address(currency0),
        Token::Address(currency1),
        Token::Uint(U256::from(fee)),
        Token::Int(U256::from(tick_spacing)),
        Token::Address(hooks),
    ])]));
    let liquidity = state_view.get_liquidity(pool_id.into()).call().await?;
    println!("Pool liquidity: {}", liquidity);

    // Spot price
    let (spot_price, current_tick) = get_spot_price(client.clone(), currency0, currency1, fee, tick_spacing, hooks).await?;
    if current_tick.abs() > 887272 {
        return Err(eyre::eyre!("Pool tick out of bounds: {}", current_tick));
    }
    
    // Get decimals for accurate min out
    let dec_in = if currency0 == H160::zero() { 18 } else { ERC20Dec::new(currency0, client.clone()).decimals().call().await.unwrap_or(18) } as u32;
    let dec_out = if currency1 == H160::zero() { 18 } else { ERC20Dec::new(currency1, client.clone()).decimals().call().await.unwrap_or(18) } as u32;
    
    // Set amount_out_min to 0 as requested
    let amount_out_min = U256::from(0u64);
    println!("Spot price: {}, amount_out_min: {}", spot_price, amount_out_min);

    // Encode V4 actions - proper order is critical
    let pool_key = (currency0, currency1, fee, tick_spacing, hooks);

    // CRITICAL: Actions must be in the right order
    let actions_bytes = Bytes::from(vec![
        0x06u8, // V4_SWAP: SWAP_EXACT_IN_SINGLE first
        0x0fu8, // TAKE_ALL second
        0x0cu8, // SETTLE_ALL third
    ]);

    // Encode swap parameters (PoolKey tuple, zeroForOne, amountIn, amountOutMin, hookData)
    let encoded_swap = ethers::abi::encode(&[Token::Tuple(vec![
        Token::Tuple(vec![
            Token::Address(pool_key.0),
            Token::Address(pool_key.1),
            Token::Uint(U256::from(pool_key.2)),          // fee uint24
            Token::Int(U256::from(pool_key.3)),           // tickSpacing int24
            Token::Address(pool_key.4),                   // hooks
        ]),
        Token::Bool(zero_for_one),
        Token::Uint(amount_to_move),                      // amountIn (uint128)
        Token::Uint(amount_out_min),                      // amountOutMin (uint128) - set to 0
        Token::Bytes(vec![]),                             // hookData - MUST BE EMPTY
    ])]);

    // CRITICAL: Fix the TAKE_ALL encoding (it takes token and minAmount, not recipient)
    let encoded_take_all = ethers::abi::encode(&[Token::Tuple(vec![
        Token::Address(LINK.parse::<H160>()?),
        Token::Uint(amount_out_min),                      // minAmount, not recipient
    ])]);

    // Encode settle_all parameters
    let encoded_settle_all = ethers::abi::encode(&[Token::Tuple(vec![
        Token::Address(USDC.parse::<H160>()?),
        Token::Uint(amount_to_move),
    ])]);

    // Build the V4_SWAP input bytes (tuple of bytes actions and array of bytes params)
    let v4_swap_input_bytes = ethers::abi::encode(&[
        Token::Bytes(actions_bytes.to_vec()),
        Token::Array(vec![
            Token::Bytes(encoded_swap),      // First action (SWAP_EXACT_IN_SINGLE)
            Token::Bytes(encoded_take_all),  // Second action (TAKE_ALL)
            Token::Bytes(encoded_settle_all), // Third action (SETTLE_ALL)
        ]),
    ]);

   // --- Build and sign Permit2 PermitSingle, then encode PERMIT2_PERMIT input ---
    // Use a max permit amount (2^160 - 1) like the Python reference
    let max_permit_amount = {
        let one: U256 = U256::from(1u64);
        // (1 << 160) - 1
        (one << 160) - one
    };

    // expiration and nonce for the PermitSingle (example values)
    // let permit_expiration: u64 = current_timestamp + 30 * 24 * 3600; // 30 days
    // let permit_nonce: u64 = 0u64;
    // // use a far-future signature deadline to avoid SignatureExpired
    // let sig_deadline = U256::MAX;

let permit2 = Permit2::new(PERMIT2_CONTRACT.parse::<H160>()?, client.clone());
let owner = client.signer().address();
let ( _amt, _exp, onchain_nonce ) = permit2
    .allowance(owner, USDC.parse()?, UNIVERSAL_ROUTER_V4.parse()?)
    .call()
    .await?;


let permit_amount = max_permit_amount;                // use the SAME value for signing + calldata
let permit_expiration: u64 = current_timestamp + 30 * 24 * 3600;
let permit_nonce: u64 = onchain_nonce;       // MUST match on-chain
let sig_deadline = U256::from(9999999999u64);   

    // Build the EIP-712 digest using the helper
    // let permit_hash = build_permit2_digest(
    //     USDC.parse::<H160>()?,         // token
    //     max_permit_amount,            // amount (U256)
    //     permit_expiration,            // expiration (u64)
    //     permit_nonce,                 // nonce (u64)
    //     UNIVERSAL_ROUTER_V4.parse::<H160>()?, // spender
    //     sig_deadline,                 // sig_deadline (U256)
    //     11155111u64,                  // chain_id
    //     PERMIT2_CONTRACT.parse::<H160>()?, // verifying_contract
    // );

    // let permit_hash = build_permit2_digest_dynamic(
    //     USDC.parse()?,                     // token
    //     permit_amount,                     // amount (<= 2^160-1)
    //     permit_expiration,                 // expiration (uint48)
    //     permit_nonce,                      // nonce (uint48)
    //     UNIVERSAL_ROUTER_V4.parse()?,      // spender
    //     sig_deadline,                      // sigDeadline
    //     11155111u64,                       // chain_id = Sepolia
    //     PERMIT2_CONTRACT.parse()?,         // verifying_contract
    // );


    // // Sign the EIP-712 digest with the current signer (SignerMiddleware inside `client`)
    // // H256 conversion
    // let permit_hash_h256 = H256::from(permit_hash);
    // let signature: Signature = client.signer().sign_hash(permit_hash_h256).map_err(|e| eyre::eyre!("Signing error: {}", e))?;
    // let mut sig_bytes = signature.to_vec();
    // // Normalize v to 27/28 if needed (match reference code)
    // if sig_bytes.len() == 65 {
    //     let v = sig_bytes[64];
    //     if v < 27 { sig_bytes[64] = v + 27; }
    // }
    // let signature_bytes = sig_bytes;

    // // Encode PERMIT2_PERMIT input: (PermitSingle struct, bytes signature)
    // let permit_input_bytes = ethers::abi::encode(&[
    //     Token::Tuple(vec![
    //         Token::Tuple(vec![
    //             Token::Address(USDC.parse()?),
    //             Token::Uint(permit_amount),
    //             Token::Uint(U256::from(permit_expiration)),
    //             Token::Uint(U256::from(permit_nonce)),
    //         ]),
    //         Token::Address(UNIVERSAL_ROUTER_V4.parse()?),
    //         Token::Uint(sig_deadline),
    //     ]),
    //     Token::Bytes(signature_bytes.clone()),
    // ]);
let max_u160 = ((U256::one() << 160) - 1);
let permit_amount = max_u160;
let permit_expiration = current_timestamp + 30 * 24 * 3600; // fits in uint48
let permit_sig_deadline = U256::from(permit_expiration);


    let local: LocalWallet = client.signer().clone().with_chain_id(11155111u64);
    let (sig65, details, spender, sig_deadline) = sign_permit2_permit_single(
        &local,
        11155111,
        PERMIT2_CONTRACT.parse()?,
        USDC.parse()?,
        permit_amount,
        permit_expiration,
        onchain_nonce as u64,
        UNIVERSAL_ROUTER_V4.parse()?,
        sig_deadline,
    ).await?;

    // 3) Encode UR input for command 0x0a
    let permit_input = encode_permit2_permit_input(details, spender, sig_deadline, &sig65);

    // Build commands and inputs: PERMIT2_PERMIT (0x0a) first, then V4_SWAP (0x10)
    let commands = Bytes::from(vec![0x0a, 0x10]);
    let inputs   = vec![permit_input, Bytes::from(v4_swap_input_bytes)];
    let universal_router = UniversalRouter::new(UNIVERSAL_ROUTER_V4.parse::<H160>()?, client.clone());
    let calldata = universal_router
        .execute(commands, inputs, deadline)
        .calldata()
        .ok_or_else(|| eyre::eyre!("Failed to encode calldata"))?;
    println!("Generated calldata: 0x{}", hex::encode(&calldata));



    // Create transaction request
    let tx = TransactionRequest::new()
        .to(UNIVERSAL_ROUTER_V4.parse::<H160>()?)
        .from(client.signer().address())
        .data(calldata)
        .gas(U256::from(1_000_000u64)) // Adjust gas limit as needed
        .gas_price(U256::from(30_000_000_000u64)); // 30 gwei

    // Simulate
    println!("Simulating transaction...");
    match simulate_with_revert_decoding(client.clone(), tx.clone()).await {
        Ok(data) => println!("Simulation successful: 0x{}", hex::encode(data)),
        Err(e) => {
            println!("Simulation failed: {}", e);
            print_revert_hex_from_error(&e);
        }
    }

    // Send
    println!("Sending transaction...");
    let pending = client.send_transaction(tx, None).await?;
    let receipt = pending.await?;
    println!("Transaction sent! Receipt: {:?}", receipt);

    Ok(())
}