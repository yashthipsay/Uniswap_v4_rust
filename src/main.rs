use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::{DynSolValue, JsonAbiExt},
    json_abi::JsonAbi,
    primitives::{address, Address, Bytes, TxKind, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{BlockNumberOrTag, TransactionRequest},
    signers::{local::PrivateKeySigner, Signer},
    sol, transports::http::Http,
};
use eyre::Result;
use std::{env, time::{SystemTime, UNIX_EPOCH}};

// Contract addresses
const UNIVERSAL_ROUTER_V4: Address = address!("0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b");
const PERMIT2_CONTRACT: Address = address!("0x000000000022D473030F116dDEE9F6B43aC78BA3");

// Token addresses (example tokens on Sepolia)
const USDC: Address = address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
const LINK: Address = address!("0x779877A7B0D9E8603169DdbD7836e478b4624789");

sol! {
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

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    dotenv::dotenv().ok();
    
    let rpc_url = env::var("ETH_RPC_URL").unwrap_or_else(|_| "https://sepolia.infura.io/v3/YOUR_KEY".to_string());
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    
    // Setup provider and signer
let signer = PrivateKeySigner::from_slice(
    &hex::decode(private_key.strip_prefix("0x").unwrap_or(&private_key))?
)?;
let provider = ProviderBuilder::new()
    .wallet(signer.clone())  // attach signer here
    .on_http(rpc_url.parse()?)
    ;
        
    // Define swap parameters
    let amount_to_move = U256::from(100_000_000_000_000u128); // 0.0001 tokens with 18 decimals
    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let deadline = U256::from(current_ts + 3000); // 50 minutes
    
    // Pool parameters
    let fee_u32 = 3000u32; // 0.3%
    let tick_spacing_i32 = 60;
    let hooks = Address::ZERO;
    
    // Create pool key ensuring correct ordering
    let zero_for_one = USDC < LINK;
    let (currency0, currency1) = if zero_for_one { (USDC, LINK) } else { (LINK, USDC) };
    
    // --- STEP 1: Build the transaction commands and inputs ---
    
    // Command byte sequence: [PERMIT2_TRANSFER_FROM (0x02), V4_SWAP (0x10)]
    let commands: Bytes = vec![0x02u8, 0x10u8].into();
    
    // --- STEP 2: Build the PERMIT2_TRANSFER_FROM input ---
    
    // PERMIT2_TRANSFER_FROM params: (address token, address recipient, uint160 amount)
    let permit_transfer_input = DynSolValue::Tuple(vec![
        DynSolValue::Address(USDC),
        DynSolValue::Address(UNIVERSAL_ROUTER_V4), // Transfer tokens to the router
        DynSolValue::Uint(amount_to_move, 160),
    ]).abi_encode();
    
    // --- STEP 3: Build the V4_SWAP input ---
    
    // V4 action bytes for: [SWAP_EXACT_IN_SINGLE (0x06), SETTLE_ALL (0x0c), TAKE_ALL (0x0f)]
    let v4_actions_bytes: Bytes = vec![0x06u8, 0x0cu8, 0x0fu8].into();
    
    // 3.1 SWAP_EXACT_IN_SINGLE params
    let pool_key_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(currency0),
        DynSolValue::Address(currency1),
        DynSolValue::Uint(U256::from(fee_u32), 24),
        DynSolValue::Int(alloy::primitives::I256::try_from(tick_spacing_i32 as i64).expect("tick_spacing_i32 fits in i64"), 24),
        DynSolValue::Address(hooks),
    ]);
    
    let exact_in_tuple = DynSolValue::Tuple(vec![
        pool_key_tuple,
        DynSolValue::Bool(zero_for_one),
        DynSolValue::Uint(amount_to_move, 128),
        DynSolValue::Uint(U256::from(0), 128), // amount_out_min (no slippage for demo)
        DynSolValue::Bytes(vec![]), // hook_data (empty)
    ]);
    
    // 3.2 SETTLE_ALL params
    let settle_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(USDC),
        DynSolValue::Uint(amount_to_move, 256),
    ]);
    let encoded_settle = settle_tuple.abi_encode();
    
    // 3.3 TAKE_ALL params
    let take_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(LINK),
        DynSolValue::Uint(U256::ZERO, 256),
    ]);
    let encoded_take = take_tuple.abi_encode();
    
    // 3.4 Combine all V4 action arguments
    let v4_arguments = DynSolValue::Array(vec![
        DynSolValue::Bytes(exact_in_tuple.abi_encode()),
        DynSolValue::Bytes(encoded_settle),
        DynSolValue::Bytes(encoded_take),
    ]);
    
    // 3.5 Encode V4_SWAP input
    let encoded_v4_swap_input = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(v4_actions_bytes.to_vec()),
        v4_arguments,
    ]).abi_encode();
    
    // --- STEP 4: Combine all inputs for Universal Router execute ---
    
    let inputs_vec = vec![
        DynSolValue::Bytes(permit_transfer_input),
        DynSolValue::Bytes(encoded_v4_swap_input),
    ];
    
    // --- STEP 5: Create the transaction ---
    
    // Build calldata for execute(bytes commands, bytes[] inputs, uint256 deadline)
    use alloy::primitives::keccak256;
    
    let function_selector = &keccak256("execute(bytes,bytes[],uint256)".as_bytes())[0..4];
    let encoded_params = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(commands.to_vec()),
        DynSolValue::Array(inputs_vec),
        DynSolValue::Uint(deadline, 256),
    ]).abi_encode();
    
    let mut calldata = Vec::new();
    calldata.extend_from_slice(function_selector);
    calldata.extend_from_slice(&encoded_params);
    
    // Create transaction request
    let tx = TransactionRequest {
        to: Some(TxKind::Call(UNIVERSAL_ROUTER_V4)),
        input: calldata.into(),
        ..Default::default()
    };
    
    // --- STEP 6: Simulate and send the transaction ---
    
    // Simulate first
    println!("Simulating transaction...");
    let call_res = provider.call(tx.clone())
        .block(BlockNumberOrTag::Latest.into())
        .await;
        
    match call_res {
        Ok(data) => {
            println!("Call succeeded: 0x{}", hex::encode(data));
        }
        Err(alloy::providers::ProviderError::JsonRpcClient { code, data, message }) => {
            println!("RPC error code: {code}, message: {message}");
            if let Some(raw) = data {
                println!("Revert raw data: 0x{}", hex::encode(raw.clone()));
            }
        }
        Err(e) => eprintln!("Unexpected error: {e}"),
    };

    // Send the transaction
    println!("Sending transaction...");
    let tx = TransactionRequest {
        gas: Some(500_000u64),
        from: Some(signer.address()), // Make sure to include it here too
        ..tx
    };
    
    let pending_tx = provider.send_transaction(tx).await?;
    println!("Transaction sent! Hash: {}", pending_tx.tx_hash());
    
    // Wait for receipt
    match pending_tx.watch().await {
        Ok(receipt_hash) => {
            println!("Transaction confirmed with hash: {receipt_hash:?}");
            
            // Get full receipt
            if let Some(receipt) = provider.get_transaction_receipt(receipt_hash).await? {
                let status = receipt.status();
                if status {
                    println!("✅ Transaction succeeded!");
                } else {
                    println!("❌ Transaction failed");
                }
            }
        },
        Err(e) => println!("Error waiting for transaction: {e}"),
    }
    
    Ok(())
}