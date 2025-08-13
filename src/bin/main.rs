use alloy::{
    dyn_abi::DynSolValue,
    primitives::{address, Address, Bytes, TxKind, B256, U160, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{BlockNumberOrTag, TransactionRequest},
    signers::{local::PrivateKeySigner, Signer},
    sol,
    sol_types::{eip712_domain, SolStruct},
};
use alloy::transports::RpcError;
use alloy_primitives::{aliases::U48, keccak256, I256};
use alloy_primitives::aliases::{U24, I24};
use eyre::Result;
use std::{env, time::{SystemTime, UNIX_EPOCH}};

// Contract addresses
const UNIVERSAL_ROUTER_V4: Address = address!("0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b");
const PERMIT2_CONTRACT: Address = address!("0x000000000022D473030F116dDEE9F6B43aC78BA3");
const STATE_VIEW: Address = address!("0xE1Dd9c3fA50EDB962E442f60DfBc432e24537E4C");

// Token addresses
const USDC: Address = address!("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238");
const LINK: Address = address!("0x779877a7b0d9e8603169ddbd7836e478b4624789");

sol! {
    #[derive(Debug)]
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    #[derive(Debug)]
    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    #[derive(Debug)]
    struct SettleAllParams {
        address token;
        uint256 amount;
    }

    #[derive(Debug)]
    struct TakeAllParams {
        address token;
        uint256 minAmount;
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract IERC20 {
        function name() external view returns (string memory);
        function symbol() external view returns (string memory);
        function decimals() external view returns (uint8);
        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);

        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
    }
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Permit2,
    "src/abis/Permit2.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    UniversalRouter,
    "src/abis/UniversalRouter.json"
);

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract StateView {
        function getLiquidity(bytes32 poolId) external view returns (uint128 liquidity);
    }
}

// Create and sign a Permit2 message (updated to use max amount)
pub fn create_permit2_signable_message(
    token: Address,
    amount: U256, // Max amount (2^160 - 1)
    expiration: u64,
    nonce: u64,
    spender: Address,
    sig_deadline: U256,
    chain_id: u64,
    verifying_contract: Address,
) -> Result<(PermitSingle, B256)> {
    let domain = eip712_domain! {
        name: "Permit2",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    };

    // Correct U160 from U256 limbs (low 3 limbs for 160 bits)
    let amount_u160: U160 = if amount > U256::from(U160::MAX) {
        return Err(eyre::eyre!("Amount exceeds U160::MAX"));
    } else {
        amount.to::<U160>()
    };

    let details = PermitDetails {
        token,
        amount: amount_u160,
        expiration: U48::from(expiration),
        nonce: U48::from(nonce),
    };

    let permit_single = PermitSingle {
        details,
        spender,
        sigDeadline: sig_deadline,
    };

    let hash = permit_single.eip712_signing_hash(&domain);
    Ok((permit_single, hash))
}

// Decode revert reason
fn decode_revert_reason(data: &[u8]) -> Option<String> {
    if data.len() >= 4 && &data[0..4] == [0x08, 0xc3, 0x79, 0xa0] {
        if data.len() >= 4 + 32 + 32 {
            let str_len = U256::from_be_bytes::<32>(data[4+32..4+64].try_into().ok()?).to::<usize>();
            let start = 4 + 64;
            let end = start + str_len;
            if data.len() >= end {
                return Some(String::from_utf8_lossy(&data[start..end]).into());
            }
        }
    }
    None
}

// Enhanced simulation with custom error decoding
async fn simulate_with_revert_decoding<P: Provider>(provider: &P, tx: TransactionRequest) -> Result<Bytes> {
    match provider.call(tx.clone()).block(BlockNumberOrTag::Latest.into()).await {
        Ok(data) => Ok(data),
        Err(RpcError::ErrorResp(err)) => {
            if let Some(data) = &err.data {
                if let Ok(hex_data) = serde_json::from_str::<String>(data.get()) {
                    let revert_bytes = hex::decode(hex_data.strip_prefix("0x").unwrap_or(&hex_data))?;
                    if let Some(reason) = decode_revert_reason(&revert_bytes) {
                        return Err(eyre::eyre!("Revert reason: {}", reason));
                    } else if revert_bytes.len() >= 4 {
                        let selector = hex::encode(&revert_bytes[0..4]);
                        // Expanded error map (PoolManager and Permit2)
                        let error_map = [
                            ("0x9860a0a9", "PoolNotInitialized"),
                            ("0x7c0b7d22", "V4TooLittleReceived"),
                            ("0x9d5e7b97", "V4TooMuchRequested"),
                            ("0x4a4f6a7d", "PoolLocked"),
                            ("0x1b9263bb", "InvalidDelta"),
                            ("0x5d1d0f9f", "InputLengthMismatch"),
                            ("0x8baa579f", "InvalidSignature"), // Permit2
                            ("0x5b0d3c3d", "InvalidNonce"), // Permit2
                            ("0x3a0a5c7b", "ExpiredPermit"), // Permit2
                            ("0x5c5a9f0e", "InvalidSigner"), // Permit2
                            ("0x0c49ccbe", "ExcessiveInvalidation"), // Permit2
                        ];
                        for (sel, name) in error_map.iter() {
                            if selector == *sel {
                                return Err(eyre::eyre!("Custom error: {}", name));
                            }
                        }
                        return Err(eyre::eyre!("Unknown custom error selector: 0x{}, raw data: 0x{}", selector, hex::encode(&revert_bytes)));
                    }
                }
            }
            Err(eyre::eyre!("Simulation reverted without decodable reason, raw error: {:?}", err))
        }
        Err(e) => Err(e.into()),
    }
}

// Check pool liquidity
async fn check_pool_liquidity<P: Provider>(provider: &P, token0: Address, token1: Address, fee: U24, tick_spacing: I24, hooks: Address) -> Result<u128> {
    let state_view = StateView::new(STATE_VIEW, provider);
    let pool_key_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(token0),
        DynSolValue::Address(token1),
        DynSolValue::Uint(U256::from(fee), 24),
        DynSolValue::Int(I256::from(tick_spacing), 24),
        DynSolValue::Address(hooks),
    ]);
    let pool_id = keccak256(pool_key_tuple.abi_encode());
    println!("Pool ID: 0x{}", hex::encode(pool_id));
    let liquidity = state_view.getLiquidity(pool_id).call().await?;
    Ok(liquidity)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    dotenv::dotenv().ok();
    let rpc_url = env::var("ETH_RPC_URL").unwrap_or_else(|_| "https://rpc.ankr.com/eth_sepolia/e2a1f8575bdf5101891a705f337daa3557709da7ff9d00237390d9e49b18d346".to_string());
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

    // Setup provider and signer
    let signer = PrivateKeySigner::from_slice(
        &hex::decode(private_key.strip_prefix("0x").unwrap_or(&private_key))?
    )?;
    let provider = ProviderBuilder::new()
        .wallet(signer.clone())
        .connect_http(rpc_url.parse()?);

    // Define swap parameters
    let amount_to_move = U256::from(2_000_000u128); // 2 USDC (6 decimals)
    let max_permit_amount = U256::MAX >> (256 - 160); // 2^160 - 1
    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let deadline = U256::from(current_ts + 3000); // 50 minutes
    let fee_u24 = U24::try_from(3000)?; // 0.3%
    let tick_spacing_i24 = I24::try_from(60)?;
    let hooks = Address::ZERO;

    // Pool parameters - ensure proper currency ordering
    let zero_for_one = USDC < LINK;
    let (currency0, currency1) = if USDC < LINK { (USDC, LINK) } else { (LINK, USDC) };
    println!("Currency0: {:?}, Currency1: {:?}, ZeroForOne: {}", currency0, currency1, zero_for_one);

    // check liquidity (unchanged)
    let liquidity = check_pool_liquidity(&provider, currency0, currency1, fee_u24, tick_spacing_i24, hooks).await?;
    println!("Pool liquidity: {}", liquidity);
    if liquidity == 0 {
        println!("WARNING: Pool has zero liquidity. Swap will likely fail. Consider minting a position.");
    }

    // Approve Permit2 for USDC
    // let usdc_token = IERC20::new(USDC, &provider);
    // let approve_receipt = usdc_token
    //     .approve(PERMIT2_CONTRACT, U256::MAX)
    //     .send()
    //     .await?
    //     .watch()
    //     .await?;
    // println!("Permit2 approved for USDC in tx: {:?}", approve_receipt);

    // Fetch Permit2 nonce
    let permit2 = Permit2::new(PERMIT2_CONTRACT, provider.clone());
    let universal_router = UniversalRouter::new(UNIVERSAL_ROUTER_V4, provider.clone());
    let allowance_call = permit2.allowance(signer.address(), USDC, UNIVERSAL_ROUTER_V4);
    let Permit2::allowanceReturn { amount, expiration, nonce } = allowance_call.call().await?;
    println!("Fetched Permit2 allowance: amount={}, expiration={}, nonce={}", amount, expiration, nonce);

    let (permit_single, hash) = create_permit2_signable_message(
        USDC,
        max_permit_amount,
        current_ts + 30 * 24 * 3600, // 30 days expiration
        nonce.to::<u64>(),
        UNIVERSAL_ROUTER_V4,
        deadline,
        11155111, // Sepolia chain ID
        PERMIT2_CONTRACT,
    )?;
    println!("Permit hash: 0x{}", hex::encode(hash));
    let signature = signer.sign_hash(&hash).await?;
    let mut sig_bytes = signature.as_bytes().to_vec();
    if sig_bytes.len() == 65 {
        let v = sig_bytes[64];
        if v < 27 { sig_bytes[64] = v + 27; }
    } else {
        return Err(eyre::eyre!("unexpected signature length: {}", sig_bytes.len()));
    }
    let signature_bytes = Bytes::from(sig_bytes);
    println!("PermitSingle signed. Signature: {:?}", signature_bytes);

    // Use correct Universal Router commands
    let commands: Bytes = vec![0x00].into();

    // Build permit input as raw encoded bytes (not wrapped in DynSolValue)
let permit_input_encoded = DynSolValue::Tuple(vec![
    // Flatten PermitDetails fields:
    DynSolValue::Address(permit_single.details.token),
    DynSolValue::Uint(U256::from(permit_single.details.amount), 160),
    DynSolValue::Uint(U256::from(permit_single.details.expiration.to::<u64>()), 48),
    DynSolValue::Uint(U256::from(permit_single.details.nonce.to::<u64>()), 48),
    // Then the rest of PermitSingle:
    DynSolValue::Address(permit_single.spender),
    DynSolValue::Uint(permit_single.sigDeadline, 256),
    DynSolValue::Bytes(signature_bytes.to_vec()),
]).abi_encode();

    // V4_SWAP actions - proper order: SWAP_EXACT_IN_SINGLE (0x06), TAKE_ALL (0x0f), SETTLE_ALL (0x0c)
    let v4_actions_bytes: Bytes = vec![0x06, 0x0f, 0x0c].into();

    // SWAP_EXACT_IN_SINGLE params
    let pool_key_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(currency0),
        DynSolValue::Address(currency1),
        DynSolValue::Uint(U256::from(fee_u24), 24),
        DynSolValue::Int(I256::from(tick_spacing_i24), 24),
        DynSolValue::Address(hooks),
    ]);
    
    let amount_out_min = U256::from(0);
    let hook_data = DynSolValue::Bytes(vec![]);
    let exact_in_tuple = DynSolValue::Tuple(vec![
        pool_key_tuple,
        DynSolValue::Bool(zero_for_one),
        DynSolValue::Uint(amount_to_move, 128),
        DynSolValue::Uint(amount_out_min, 128),
        hook_data,
    ]);
    let encoded_swap = exact_in_tuple.abi_encode();

    // TAKE_ALL params
    let take_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(LINK),
        DynSolValue::Uint(U256::ZERO, 256),
    ]);
    let encoded_take = take_tuple.abi_encode();

    // SETTLE_ALL params
    let settle_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(USDC),
        DynSolValue::Uint(amount_to_move, 256),
    ]);
    let encoded_settle = settle_tuple.abi_encode();

    println!("permit_input length: {}", permit_input_encoded.len());
    println!("encoded_swap length: {}", encoded_swap.len());
    println!("encoded_take length: {}", encoded_take.len());
    println!("encoded_settle length: {}", encoded_settle.len());

    // Combine V4 action args in the correct order: swap -> take -> settle
    let v4_arguments = DynSolValue::Array(vec![
        DynSolValue::Bytes(encoded_swap),
        DynSolValue::Bytes(encoded_take),
        DynSolValue::Bytes(encoded_settle),
    ]);
    let encoded_v4_swap_input = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(v4_actions_bytes.to_vec()),
        v4_arguments,
    ]).abi_encode();

    // Create inputs array with raw bytes (not double-wrapped)
    // let inputs_array = DynSolValue::Array(vec![
    //     DynSolValue::Bytes(permit_input_encoded),
    //     DynSolValue::Bytes(encoded_v4_swap_input),
    // ]);

    // // Build the complete function call
    // let execute_call = DynSolValue::Tuple(vec![
    //     DynSolValue::Bytes(commands.to_vec()),
    //     inputs_array,
    //     DynSolValue::Uint(deadline, 256),
    // ]);

    let inputs_vec = vec![
        // permit_input_encoded,
        encoded_v4_swap_input,
    ];

    // Get function selector and encode parameters as a single tuple
    let function_selector = &keccak256("execute(bytes,bytes[],uint256)".as_bytes())[0..4];
    
    // Encode all three parameters as a single tuple
    let all_params = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(commands.to_vec()),
        DynSolValue::Array(
            inputs_vec.into_iter().map(|bytes| DynSolValue::Bytes(bytes)).collect()
        ),
        DynSolValue::Uint(deadline, 256),
    ]);
    
    let encoded_params = all_params.abi_encode();
    
    let mut calldata = function_selector.to_vec();
    calldata.extend(encoded_params);

    println!("Rust-generated calldata: 0x{}", hex::encode(&calldata));

    let tx = TransactionRequest {
        to: Some(TxKind::Call(UNIVERSAL_ROUTER_V4)),
        input: calldata.into(),
        from: Some(signer.address()),
        gas: Some(500_000u64),
        max_priority_fee_per_gas: Some(1_000_000_000u128),
        max_fee_per_gas: Some(30_000_000_000u128),
        ..Default::default()
    };

    // Simulate transaction (with enhanced revert decoding)
    println!("Simulating transaction…");
    match simulate_with_revert_decoding(&provider, tx.clone()).await {
        Ok(data) => {
            println!("Simulation successful! Return data: 0x{}", hex::encode(&data));
        }
        Err(e) => {
            println!("Simulation failed: {}", e);
        }
    }

    // Always send the transaction, so you can get an on-chain trace/receipt
    println!("Sending transaction...");
    let pending = provider.send_transaction(tx.clone()).await?;
    let receipt = pending.watch().await?;
    println!("Transaction sent! Receipt: {:?}", receipt);

    Ok(())
}