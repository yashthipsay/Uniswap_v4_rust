use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::{DynSolValue, JsonAbiExt},
    json_abi::JsonAbi,
    primitives::{address, Address, Bytes, B256, TxKind, U256, U160},
    providers::{Provider, ProviderBuilder},
    rpc::types::{BlockNumberOrTag, TransactionRequest},
    signers::{local::PrivateKeySigner, Signer},
    sol, transports::http::Http,
    sol_types::{eip712_domain, SolStruct, SolValue}
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
    contract Permit2 {
        function allowance(address owner, address token, address spender) external view returns (uint160 amount, uint48 expiration, uint48 nonce);
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
async fn check_pool_liquidity<P: Provider>(provider: &P, token0: Address, token1: Address, fee: u32, tick_spacing: i32, hooks: Address) -> Result<u128> {
    let state_view = StateView::new(STATE_VIEW, provider.clone());
    let pool_key_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(token0),
        DynSolValue::Address(token1),
        DynSolValue::Uint(U256::from(U24::try_from(fee)?), 24),
        DynSolValue::Int(I256::from(I24::try_from(tick_spacing)?), 24),
        DynSolValue::Address(hooks),
    ]);
    let pool_id = keccak256(pool_key_tuple.abi_encode());
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
        .on_http(rpc_url.parse()?);

    // Define swap parameters
    let amount_to_move = U256::from(1_000_000u128); // 1 USDC (6 decimals)
    let max_permit_amount = U256::MAX >> (256 - 160); // 2^160 - 1
    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let deadline = U256::from(current_ts + 3000); // 50 minutes
    let fee = 3000u32; // 0.3%
    let tick_spacing = 60i32;
    let hooks = Address::ZERO;

    // Pool parameters
    let zero_for_one = USDC < LINK;
    let (currency0, currency1) = if zero_for_one { (USDC, LINK) } else { (LINK, USDC) };

    // Check pool liquidity
    println!("Checking pool liquidity...");
    let liquidity = check_pool_liquidity(&provider, currency0, currency1, fee, tick_spacing, hooks).await?;
    println!("Pool liquidity: {}", liquidity);
    if liquidity == 0 {
        println!("WARNING: Pool has zero liquidity. Swap will likely fail. Consider minting a position.");
    }

    // Approve Permit2 for USDC
    let usdc_token = IERC20::new(USDC, provider.clone());
    let approve_receipt = usdc_token
        .approve(PERMIT2_CONTRACT, U256::MAX)
        .send()
        .await?
        .watch()
        .await?;
    println!("Permit2 approved for USDC in tx: {:?}", approve_receipt);

    // Fetch Permit2 nonce
    let permit2 = Permit2::new(PERMIT2_CONTRACT, provider.clone());
    let allowance_call = permit2.allowance(signer.address(), USDC, UNIVERSAL_ROUTER_V4);
    let Permit2::allowanceReturn { amount, expiration, nonce } = allowance_call.call().await?;
    println!("Fetched Permit2 allowance: amount={}, expiration={}, nonce={}", amount, expiration, nonce);

    // Create and sign Permit2 message
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

    // normalize r||s||v so v ∈ {27,28}

    // let mut sig_bytes = signature.as_bytes().to_vec();
    // if sig_bytes.len() == 65 {
    //     let v = sig_bytes[64];
    //     if v == 0 || v == 1 {
    //         sig_bytes[64] = v + 27;
    //     }
    // } else if sig_bytes.len() == 64 {
    //     return Err(eyre::eyre!(
    //         "signature is 64 bytes (compact) — need full r||s||v"
    //     ));
    // } else {
    //     return Err(eyre::eyre!(
    //         "unexpected signature length: {}",
    //         sig_bytes.len()
    //     ));
    // }

    let signature_bytes = Bytes::from(signature.as_bytes().to_vec());
    println!("PermitSingle signed. Signature: {:?}", signature_bytes);

    // Build transaction commands: [PERMIT2_PERMIT (0x0a), V4_SWAP (0x10)]
    let commands: Bytes = vec![0x0a, 0x10].into();

    // PERMIT2_PERMIT input
    let permit_input = DynSolValue::Tuple(vec![
    DynSolValue::Bytes(permit_single.abi_encode()),
        DynSolValue::Bytes(signature_bytes.to_vec()),
    ]).abi_encode();

    // V4_SWAP input: [SWAP_EXACT_IN_SINGLE (0x06), TAKE_ALL (0x0f), SETTLE_ALL (0x0c)]
    let v4_actions_bytes: Bytes = vec![0x06, 0x0c, 0x0f].into();

    // SWAP_EXACT_IN_SINGLE params
    let pool_key_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(currency0),
        DynSolValue::Address(currency1),
        DynSolValue::Uint(U256::from(fee), 24),
        DynSolValue::Int(alloy::primitives::I256::try_from(tick_spacing as i64).expect("tick_spacing fits in i64"), 24),
        DynSolValue::Address(hooks),
    ]);
    // let amount_out_min = amount_to_move * U256::from(99u8) / U256::from(100u8); // 1% slippage tolerance
    let amount_out_min = U256::from(0); // Set to 0 for no minimum
    let exact_in_tuple = DynSolValue::Tuple(vec![
        pool_key_tuple,
        DynSolValue::Bool(zero_for_one),
        DynSolValue::Uint(amount_to_move, 128),
        DynSolValue::Uint(amount_out_min, 128),
        DynSolValue::Bytes(vec![]), // hook_data
    ]);

    // TAKE_ALL params (output: LINK)
    let take_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(LINK),
        DynSolValue::Uint(U256::ZERO, 256),
    ]);
    let encoded_take = take_tuple.abi_encode();

    // SETTLE_ALL params (input: USDC)
    let settle_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(USDC),
        DynSolValue::Uint(amount_to_move, 256),
    ]);
    let encoded_settle = settle_tuple.abi_encode();

    // Combine V4 action arguments
    let v4_arguments = DynSolValue::Array(vec![
        DynSolValue::Bytes(exact_in_tuple.abi_encode()),
        DynSolValue::Bytes(encoded_settle),
        DynSolValue::Bytes(encoded_take),
    ]);
    let encoded_v4_swap_input = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(v4_actions_bytes.to_vec()),
        v4_arguments,
    ]).abi_encode();

    // Combine inputs
    let inputs_vec = vec![
        DynSolValue::Bytes(permit_input),
        DynSolValue::Bytes(encoded_v4_swap_input),
    ];

    // Build calldata for execute(bytes,bytes[],uint256)
    let function_selector = &keccak256("execute(bytes,bytes[],uint256)".as_bytes())[0..4];
    let encoded_params = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(commands.to_vec()),
        DynSolValue::Array(inputs_vec),
        DynSolValue::Uint(deadline, 256),
    ]).abi_encode();
    let mut calldata = function_selector.to_vec();
    calldata.extend(encoded_params);
    println!("Calldata: 0x{}", hex::encode(&calldata));

    // Create transaction
    let tx = TransactionRequest {
        to: Some(TxKind::Call(UNIVERSAL_ROUTER_V4)),
        input: calldata.into(),
        from: Some(signer.address()),
        gas: Some(500_000u64),
        ..Default::default()
    };

    // Simulate transaction
    println!("Simulating transaction...");
    match simulate_with_revert_decoding(&provider, tx.clone()).await {
        Ok(data) => println!("Simulation successful! Return data: 0x{}", hex::encode(data)),
        Err(e) => println!("Simulation failed: {}", e),
    }

    // Send transaction
    // println!("Sending transaction with Permit2 Permit and V4 Swap...");
    // match provider.send_transaction(tx).await {
    //     Ok(pending_tx) => {
    //         let tx_hash = pending_tx.tx_hash();
    //         println!("Transaction sent! Hash: {}", tx_hash);
    //         match pending_tx.watch().await {
    //             Ok(receipt_hash) => {
    //                 println!("Transaction confirmed with hash: {:?}", receipt_hash);
    //                 match provider.get_transaction_receipt(receipt_hash).await {
    //                     Ok(Some(receipt)) => {
    //                         if receipt.status() {
    //                             println!("✅ Transaction succeeded!");
    //                         } else {
    //                             println!("❌ Transaction failed");
    //                         }
    //                     }
    //                     Ok(None) => println!("Receipt not found"),
    //                     Err(e) => println!("Error getting receipt: {}", e),
    //                 }
    //             }
    //             Err(e) => println!("Error waiting for transaction: {}", e),
    //         }
    //     }
    //     Err(e) => println!("Error sending transaction: {}", e),
    // }

    Ok(())
}