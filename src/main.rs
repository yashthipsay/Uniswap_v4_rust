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
use alloy_primitives::aliases::U48;
use alloy::transports::RpcError;
use eyre::Result;
use std::{env, time::{SystemTime, UNIX_EPOCH}};

// Contract addresses
const UNIVERSAL_ROUTER_V4: Address = address!("0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b");
const PERMIT2_CONTRACT: Address = address!("0x000000000022D473030F116dDEE9F6B43aC78BA3");

// Token addresses (example tokens on Sepolia)
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

// Create and sign a Permit2 message
pub fn create_permit2_signable_message(
    token: Address,
    amount: U256,
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

    let details = PermitDetails {
        token,
        amount: U160::from(amount.to::<u64>()),
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
        .wallet(signer.clone())
        .on_http(rpc_url.parse()?);
        
    // Define swap parameters
    let amount_to_move = U256::from(1_000_000u128); // 0.0001 tokens with 18 decimals
    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let deadline = U256::from(current_ts + 3000); // 50 minutes
    
    // Pool parameters
    let fee_u32 = 3000u32; // 0.3%
    let tick_spacing_i32 = 60;
    let hooks = Address::ZERO;
    
    // Create pool key ensuring correct ordering
    let zero_for_one = USDC < LINK;
    let (currency0, currency1) = if zero_for_one { (USDC, LINK) } else { (LINK, USDC) };

    let usdc_token = IERC20::new(USDC, provider.clone());
    let approve_receipt = usdc_token
        .approve(PERMIT2_CONTRACT, U256::MAX)
        .send()
        .await?
        .watch()
        .await?;
    println!("Permit2 approved for USDC in tx: {approve_receipt:?}");
    
    // --- STEP 1: Create and sign the Permit2 message ---
    let (permit_single, hash) = create_permit2_signable_message(
        USDC,
        amount_to_move,
        current_ts + 3600,     // expiration (1 hour from now)
        0,                     // nonce
        UNIVERSAL_ROUTER_V4,   // spender
        deadline,              // signature deadline
        11155111,              // Sepolia chain ID
        PERMIT2_CONTRACT,
    )?;

    let signature = signer.sign_hash(&hash).await?;
    let signature_bytes = Bytes::copy_from_slice(&signature.as_bytes().to_vec());
    println!("PermitSingle signed. Signature: {signature_bytes:?}");
    
    // --- STEP 2: Build the transaction commands and inputs ---
    
    // Command byte sequence: [PERMIT2_PERMIT (0x0a), V4_SWAP (0x10)]
    let commands: Bytes = vec![0x0a, 0x10].into();
    
    // --- STEP 3: Build the PERMIT2_PERMIT input ---
    
    // PERMIT2_PERMIT params: (PermitSingle permit, bytes signature)
    let permit_input = DynSolValue::Tuple(vec![
        DynSolValue::Tuple(vec![
            DynSolValue::Tuple(vec![
                DynSolValue::Address(permit_single.details.token),
                DynSolValue::Uint(U256::from(permit_single.details.amount.to::<u64>()), 160),
                DynSolValue::Uint(U256::from(permit_single.details.expiration.to::<u64>()), 48),
                DynSolValue::Uint(U256::from(permit_single.details.nonce.to::<u64>()), 48),
            ]),
            DynSolValue::Address(permit_single.spender),
            DynSolValue::Uint(permit_single.sigDeadline, 256),
        ]),
        DynSolValue::Bytes(signature_bytes.to_vec()),
    ]).abi_encode();
    
    // --- STEP 4: Build the V4_SWAP input ---
    
    // V4 action bytes for: [SWAP_EXACT_IN_SINGLE (0x06), SETTLE_ALL (0x0c), TAKE_ALL (0x0f)]
    let v4_actions_bytes: Bytes = vec![0x06u8, 0x0cu8, 0x0fu8].into();
    
    // 4.1 SWAP_EXACT_IN_SINGLE params
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
    
    // 4.2 SETTLE_ALL params
    let settle_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(USDC),
        DynSolValue::Uint(amount_to_move, 256),
    ]);
    let encoded_settle = settle_tuple.abi_encode();
    
    // 4.3 TAKE_ALL params
    let take_tuple = DynSolValue::Tuple(vec![
        DynSolValue::Address(LINK),
        DynSolValue::Uint(U256::ZERO, 256),
    ]);
    let encoded_take = take_tuple.abi_encode();
    
    // 4.4 Combine all V4 action arguments
    let v4_arguments = DynSolValue::Array(vec![
        DynSolValue::Bytes(exact_in_tuple.abi_encode()),
        DynSolValue::Bytes(encoded_settle),
        DynSolValue::Bytes(encoded_take),
    ]);
    
    // 4.5 Encode V4_SWAP input
    let encoded_v4_swap_input = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(v4_actions_bytes.to_vec()),
        v4_arguments,
    ]).abi_encode();
    
    // --- STEP 5: Combine all inputs for Universal Router execute ---
    
    let inputs_vec = vec![
        DynSolValue::Bytes(permit_input),
        DynSolValue::Bytes(encoded_v4_swap_input),
    ];
    
    // --- STEP 6: Create the transaction ---
    
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
        from: Some(signer.address()),
        ..Default::default()
    };
    
    // --- STEP 7: Simulate and send the transaction ---
    
    // Simulate first
    println!("Simulating transaction...");
    let simulation = provider
        .call(tx.clone())
        .block(BlockNumberOrTag::Latest.into())
        .await;
        
    match simulation {
        Ok(data) => {
            println!("Simulation successful! Return data: 0x{}", hex::encode(data));
        }
        Err(rpc_err) => {
            println!("Simulation failed: {rpc_err}");
            println!("Proceeding with transaction anyway...");
        }
    }

    // Send the transaction
    println!("Sending transaction with Permit2 Permit and V4 Swap...");
    let tx = TransactionRequest {
        gas: Some(500_000u64),
        from: Some(signer.address()),
        ..tx
    };
    
    match provider.send_transaction(tx).await {
        Ok(pending_tx) => {
            let tx_hash = pending_tx.tx_hash();
            println!("Transaction sent! Hash: {tx_hash}");
            
            match pending_tx.watch().await {
                Ok(receipt_hash) => {
                    println!("Transaction confirmed with hash: {receipt_hash:?}");
                    
                    match provider.get_transaction_receipt(receipt_hash).await {
                        Ok(Some(receipt)) => {
                            if receipt.status() {
                                println!("✅ Transaction succeeded!");
                            } else {
                                println!("❌ Transaction failed");
                            }
                        }
                        Ok(None) => println!("Receipt not found"),
                        Err(e) => println!("Error getting receipt: {e}"),
                    }
                },
                Err(e) => println!("Error waiting for transaction: {e}"),
            }
        },
        Err(e) => println!("Error sending transaction: {e}"),
    }
    
    Ok(())
}