use ethers::abi::Token;
use ethers::prelude::*;
use ethers::utils::{keccak256, parse_units};
use std::sync::Arc;
use eyre::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use ethers::types::transaction::eip712::*;
use ethers::types::transaction::eip2718::TypedTransaction; // for simulation
use ethers::types::*;
use ethers::middleware::gas_oracle::GasOracleMiddleware;
use ethers::providers::{Middleware, Provider, Http};
const UNIVERSAL_ROUTER_V3: &str = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD";
const PERMIT2_CONTRACT: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const USDC: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const WETH: &str = "0xfff9976782d46cc05630d1f6ebab18b2324d6b14";

abigen!(
    UniversalRouter,
    r#"[
        function execute(bytes commands, bytes[] inputs) payable
    ]"#,
);

abigen!(
    Permit2,
    r#"[ 
        function allowance(address owner, address token, address spender) external view returns (uint160 amount, uint48 expiration, uint48 nonce)
    ]"#,
);

abigen!(
    IERC20,
    r#"[
    function approve(address spender,uint256 value) external returns (bool)
    function allowance(address owner,address spender) external view returns (uint256)
    function balanceOf(address owner) external view returns (uint256)
    function decimals() external view returns (uint8)
    ]"#,
);

abigen!(
    QuoterV2,
    r#"[
        function quoteExactInput(bytes path, uint256 amountIn) external returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate)
    ]"#
);



fn encode_v3_path(tokens: &[Address], fees: &[u32]) -> Bytes {
    assert!(tokens.len() >= 2 && fees.len() == tokens.len() - 1);
    let mut v = Vec::<u8>::new();
    for (i, token) in tokens.iter().enumerate() {
        v.extend_from_slice(token.as_bytes());
        if i < fees.len() {
            let f = fees[i];
            let fee_bytes = [(f >> 16) as u8, (f >> 8) as u8, f as u8];
            v.extend_from_slice(&fee_bytes); 
        }
    }
    Bytes::from(v)
}

async fn quote_route_with_quoter_v2<M: Middleware + 'static>(
    client: Arc<M>,
    quoter_v2: Address,
    path: Bytes,
    amount_in: U256,
) -> Result<(U256, U256)> {
    let quoter = QuoterV2::new(quoter_v2, client);
    let (amount_out, _sqrt_after, _ticks, gas_estimate) = quoter.quote_exact_input(path, amount_in).call().await?;
    Ok((amount_out, gas_estimate))
}

/// Get (b, f) where:
/// b = baseFeePerGas (wei/gas)
async fn get_fees<M>(client: &M) -> eyre::Result<(U256, U256)>
where
    M: Middleware + 'static,
{
    // Base fee comes from the latest block
    let latest_block = client.get_block(ethers::types::BlockNumber::Latest).await?.unwrap();
    let base_fee = latest_block.base_fee_per_gas.unwrap_or_default();

    // Use built-in estimator for priority fee (EIP-1559 tip cap)
    let fees = client.estimate_eip1559_fees(None).await?;
    let priority_fee = fees.1;

    Ok((base_fee, priority_fee))
}


/// Calculates the baseline price of a route
///
/// # Arguments
/// * `input_amount` - amount of input tokens (i)
/// * `output_amount` - amount of output tokens (o)
/// * `gas_used` - estimated gas used for the route (g)
/// * `base_fee` - base fee per gas (b)
/// * `priority_fee` - priority fee per gas (f)
///
/// # Returns
/// Baseline price as U256 (scaled rational approximation)
pub fn baseline_price(
    amount_in: U256,          // i  (input token smallest units)
    amount_out: U256,         // o  (output token smallest units)
    gas_used: U256,           // g
    base_fee: U256,           // b (wei/gas)
    priority_fee: U256,       // f (wei/gas)
    eth_per_input_in_input_units: f64, // conversion: 1 ETH = ? input-token units
) -> f64 {
    // Gas cost in wei = g * (b + f)
    let gas_cost_wei = gas_used.saturating_mul(base_fee.saturating_add(priority_fee));

    // Convert everything to f64 for scoring (OK for routing; not safe for accounting!)
    let i_f = u256_to_f64(amount_in);
    let o_f = u256_to_f64(amount_out);

    // Convert gas cost (wei) -> input token units
    // 1 ETH = 1e18 wei, so (gas_cost_wei / 1e18) ETH * (eth_per_input_in_input_units)
    let gas_cost_input_units = u256_to_f64(gas_cost_wei) * eth_per_input_in_input_units / 1e18_f64;

    // Final price formula
    o_f / (i_f + gas_cost_input_units)
}

// Helper function to convert U256 to f64
fn u256_to_f64(value: U256) -> f64 {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    let mut result: f64 = 0.0;
    for &b in &bytes {
        result = result * 256.0 + (b as f64);
    }
    result
}

async fn ensure_approval(
    token: &IERC20<SignerMiddleware<Provider<Http>, Wallet<k256::ecdsa::SigningKey>>>,
    owner: Address,
    spender: Address,
    needed: U256,
) -> Result<()> {
    let current = token.allowance(owner, spender).call().await?;
    if current < needed {
        token.approve(spender, U256::MAX).send().await?.await?;
    }

    Ok(())
}

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

async fn estimate_route_gas<M: Middleware + 'static>(
    client: Arc<M>,
    to: Address,
    from: Address,
    calldata: Bytes,
    value: U256,
) -> Result<U256> {
    let tx = TransactionRequest::new()
        .to(to)
        .from(from)
        .value(value)
        .data(calldata);

    let typed_tx: TypedTransaction = tx.into();
    let gas_estimate = client.estimate_gas(&typed_tx, None).await?;
    Ok(gas_estimate)
}

#[tokio::main()]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();


    let rpc = std::env::var("ETH_RPC_URL").unwrap_or_else(|_| "https://rpc.ankr.com/eth_sepolia".to_string());
    let pk = std::env::var("PRIVATE_KEY")?;
    let provider = Provider::<Http>::try_from(rpc)?;
    let wallet   = pk.parse::<LocalWallet>()?.with_chain_id(11155111u64);
    let client = Arc::new(SignerMiddleware::new(provider, wallet.clone()));
    let sender = client.address();


    let ur_addr: Address = UNIVERSAL_ROUTER_V3.parse()?;
    let permit2_addr: Address = PERMIT2_CONTRACT.parse()?;
    let token_in: Address = USDC.parse()?;
    let token_mid: Address = "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984".parse()?;
    let token_out: Address = WETH.parse()?;

    let amount_in = parse_units("5.0", 6)?;

    let expiration: u64 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_secs() + 3600);

    let permit2= Permit2::new(permit2_addr, client.clone());
    let (allowance_amount, allowance_expiration, allowance_nonce) = permit2.allowance(sender, token_in, ur_addr).call().await?;

    let nonce  = allowance_nonce;

    let sig_deadline = U256::from(expiration as u128 + 3600);

    let (sig65, details, spender, sig_deadline_u256) = sign_permit2_permit_single(
        &wallet,
        11155111,
        permit2_addr,
        token_in,
        amount_in.into(),
        expiration,
        nonce,
        ur_addr,
        sig_deadline.into(),
    ).await?;

    let permit_input = encode_permit2_permit_input(details, spender, sig_deadline_u256, &sig65);

    let path = encode_v3_path(&[token_in, token_mid, token_out], &[500, 500]);

    let recipient = Token::Address(sender);
    let amount_in_t = Token::Uint(amount_in.into());
    // Amount out should be zero
    let amount_out_min = Token::Int(U256::zero());
    let path_t = Token::Bytes(path.to_vec());
    let payer_is_user = Token::Bool(true);
    let sqrtpricelimitx96 = 0;

    let v3_swap_exact_in_input = {
        let encoded = abi::encode(&[
            recipient, 
            amount_in_t,
            amount_out_min,
            path_t,
            payer_is_user,
            // Token::Uint(U256::from(sqrtpricelimitx96)),
        ]);
        Bytes::from(encoded)
    };

    // ====== 4) Commands byte string ======
    // 0x0a = PERMIT2_PERMIT, 0x00 = V3_SWAP_EXACT_IN
    // (optionally prepend 0x0b for DEADLINE)
    let commands = Bytes::from(vec![0x0a, 0x00]);
    // let commands = Bytes::from(vec![0x00]);

    // ====== 5) Call Universal Router execute ======
    let ur = UniversalRouter::new(ur_addr, client.clone());

    // inputs[] must align 1:1 with commands
    let inputs: Vec<Bytes> = vec![permit_input, v3_swap_exact_in_input];
    // let inputs: Vec<Bytes> = vec![v3_swap_exact_in_input];

    let calldata = ur.execute(commands.clone(), inputs.clone()).calldata().ok_or_else(|| eyre::eyre!("Failed to encode calldata"))?;

    // True gas estimate for this UniversalRouter calldata (preferred)
    let gas_estimate_real = match estimate_route_gas(
        client.clone(),
        ur_addr,
        sender,
        calldata.clone(),
        U256::zero(),
    ).await {
        Ok(g) => g,
        Err(e) => {
            // Fallback to quoter estimate (if you have one) or a conservative default
            println!("estimate_gas failed, falling back to quoter estimate: {}", e);
            // if you keep QuoterV2 gasEst from earlier, use that here; otherwise set a default
            U256::from(300_000u64) // conservative default
        }
    };

    println!("Transaction-level gas estimate: {}", gas_estimate_real);

    let tx = TransactionRequest::new()
        .to(ur_addr)
        .from(sender)
        .value(U256::zero()) // No ETH value sent, since we are swapping tokens
        .data(calldata)
        .gas(U256::from(1_000_000u64)) // Adjust gas limit as needed
        .gas_price(U256::from(30_000_000_000u64)); // 30 gwei
    // NOTE: For ERC20->ERC20, no msg.value. For ETH paths, you’d pass value.
    // let binding = ur.execute(commands, inputs);
    // let pending = binding.send().await?;
    println!("Simulating transaction...");
    match simulate_with_revert_decoding(client.clone(), tx.clone()).await {
        Ok(data) => println!("Simulation successful: 0x{}", hex::encode(data)),
        Err(e) => {
            println!("Simulation failed: {}", e);
        }
    }

    let quoter_v2: Address = "0xEd1f6473345F45b75F8179591dd5bA1888cf2FB3".parse()?;
    let token_in: Address = USDC.parse()?;
    let token_mid: Address = "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984".parse()?;
    let token_out: Address = WETH.parse()?;
    let fees = [500, 500];

    let path2 = encode_v3_path(&[token_in, token_mid, token_out], &fees);

    let amount_in = U256::from_dec_str("5000000")?;

    let (amount_out, gas_estimate) = quote_route_with_quoter_v2(client.clone(), quoter_v2, path2, amount_in).await?;

    // 2) Get (b, f)
    let (base_fee, priority_fee) = get_fees(client.as_ref()).await?;

    // 3) ETH→input conversion:
    // If input is USDC, you need an ETH price in USDC *smallest units*.
    // Example: 1 ETH = 4_000.00 USDC → 4_000 * 1e6 = 4_000_000_000
    // You should inject this from your price source.
    let eth_per_usdc_smallest = 4_400_000_000f64; // <-- replace with live feed
    let price = baseline_price(
        amount_in,
        amount_out,
        gas_estimate_real,
        base_fee,
        priority_fee,
        eth_per_usdc_smallest,
    );

    println!("amountOut: {amount_out}");
    println!("gasEstimate from quoter: {gas_estimate}");
    println!("gasEstimate from transaction simulation: {}", gas_estimate_real);
    println!("baseFeePerGas: {base_fee}");
    println!("priorityFeePerGas: {priority_fee}");
    println!("Baseline price score: {price}");


    // Send transaction
    // let pending = client.send_transaction(tx, None).await?;
    // let receipt = pending.await?;
    // println!("Transaction receipt: {:?}", receipt);

    // println!("Swap tx: {:?}", receipt);

    Ok(())
}