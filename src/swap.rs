use alloy::{
    contract::{ContractInstance, Interface}, dyn_abi::{DynSolValue, JsonAbiExt}, json_abi::JsonAbi, primitives::{address, keccak256, Address, Bytes, TxKind, B256, U256}, providers::{ProviderBuilder, Provider}, rpc::types::{BlockNumberOrTag, TransactionRequest}, signers::{local::PrivateKeySigner, Signer}, sol, sol_types::{eip712_domain, SolStruct, SolValue}
};
use alloy_primitives::aliases::{U160, U48, U24};
use alloy_signer::Signature;
use eyre::Result;
use std::env;
use serde::{Serialize, Deserialize};

const UNIVERSAL_ROUTER_V4: Address = address!("0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b");
const PERMIT2_CONTRACT: Address = address!("0x000000000022D473030F116dDEE9F6B43aC78BA3");
const LINK: Address = address!("0x779877A7B0D9E8603169DdbD7836e478b4624789");
const USDC: Address = address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");

const UNIVERSAL_ROUTER_ABI: &str = r#"
[{"inputs":[{"components":[{"internalType":"address","name":"permit2","type":"address"},{"internalType":"address","name":"weth9","type":"address"},{"internalType":"address","name":"v2Factory","type":"address"},{"internalType":"address","name":"v3Factory","type":"address"},{"internalType":"bytes32","name":"pairInitCodeHash","type":"bytes32"},{"internalType":"bytes32","name":"poolInitCodeHash","type":"bytes32"},{"internalType":"address","name":"v4PoolManager","type":"address"},{"internalType":"address","name":"v3NFTPositionManager","type":"address"},{"internalType":"address","name":"v4PositionManager","type":"address"}],"internalType":"struct RouterParameters","name":"params","type":"tuple"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"BalanceTooLow","type":"error"},{"inputs":[],"name":"ContractLocked","type":"error"},{"inputs":[{"internalType":"Currency","name":"currency","type":"address"}],"name":"DeltaNotNegative","type":"error"},{"inputs":[{"internalType":"Currency","name":"currency","type":"address"}],"name":"DeltaNotPositive","type":"error"},{"inputs":[],"name":"ETHNotAccepted","type":"error"},{"inputs":[{"internalType":"uint256","name":"commandIndex","type":"uint256"},{"internalType":"bytes","name":"message","type":"bytes"}],"name":"ExecutionFailed","type":"error"},{"inputs":[],"name":"FromAddressIsNotOwner","type":"error"},{"inputs":[],"name":"InputLengthMismatch","type":"error"},{"inputs":[],"name":"InsufficientBalance","type":"error"},{"inputs":[],"name":"InsufficientETH","type":"error"},{"inputs":[],"name":"InsufficientToken","type":"error"},{"inputs":[{"internalType":"bytes4","name":"action","type":"bytes4"}],"name":"InvalidAction","type":"error"},{"inputs":[],"name":"InvalidBips","type":"error"},{"inputs":[{"internalType":"uint256","name":"commandType","type":"uint256"}],"name":"InvalidCommandType","type":"error"},{"inputs":[],"name":"InvalidEthSender","type":"error"},{"inputs":[],"name":"InvalidPath","type":"error"},{"inputs":[],"name":"InvalidReserves","type":"error"},{"inputs":[],"name":"LengthMismatch","type":"error"},{"inputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"NotAuthorizedForToken","type":"error"},{"inputs":[],"name":"NotPoolManager","type":"error"},{"inputs":[],"name":"OnlyMintAllowed","type":"error"},{"inputs":[],"name":"SliceOutOfBounds","type":"error"},{"inputs":[],"name":"TransactionDeadlinePassed","type":"error"},{"inputs":[],"name":"UnsafeCast","type":"error"},{"inputs":[{"internalType":"uint256","name":"action","type":"uint256"}],"name":"UnsupportedAction","type":"error"},{"inputs":[],"name":"V2InvalidPath","type":"error"},{"inputs":[],"name":"V2TooLittleReceived","type":"error"},{"inputs":[],"name":"V2TooMuchRequested","type":"error"},{"inputs":[],"name":"V3InvalidAmountOut","type":"error"},{"inputs":[],"name":"V3InvalidCaller","type":"error"},{"inputs":[],"name":"V3InvalidSwap","type":"error"},{"inputs":[],"name":"V3TooLittleReceived","type":"error"},{"inputs":[],"name":"V3TooMuchRequested","type":"error"},{"inputs":[{"internalType":"uint256","name":"minAmountOutReceived","type":"uint256"},{"internalType":"uint256","name":"amountReceived","type":"uint256"}],"name":"V4TooLittleReceived","type":"error"},{"inputs":[{"internalType":"uint256","name":"maxAmountInRequested","type":"uint256"},{"internalType":"uint256","name":"amountRequested","type":"uint256"}],"name":"V4TooMuchRequested","type":"error"},{"inputs":[],"name":"V3_POSITION_MANAGER","outputs":[{"internalType":"contract INonfungiblePositionManager","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"V4_POSITION_MANAGER","outputs":[{"internalType":"contract IPositionManager","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes","name":"commands","type":"bytes"},{"internalType":"bytes[]","name":"inputs","type":"bytes[]"}],"name":"execute","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"bytes","name":"commands","type":"bytes"},{"internalType":"bytes[]","name":"inputs","type":"bytes[]"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"execute","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"msgSender","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"poolManager","outputs":[{"internalType":"contract IPoolManager","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"int256","name":"amount0Delta","type":"int256"},{"internalType":"int256","name":"amount1Delta","type":"int256"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"uniswapV3SwapCallback","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes","name":"data","type":"bytes"}],"name":"unlockCallback","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]
"#;

const PERMIT2_ABI: &str = r#"
[{"inputs":[{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"AllowanceExpired","type":"error"},{"inputs":[],"name":"ExcessiveInvalidation","type":"error"},{"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"InsufficientAllowance","type":"error"},{"inputs":[{"internalType":"uint256","name":"maxAmount","type":"uint256"}],"name":"InvalidAmount","type":"error"},{"inputs":[],"name":"InvalidContractSignature","type":"error"},{"inputs":[],"name":"InvalidNonce","type":"error"},{"inputs":[],"name":"InvalidSignature","type":"error"},{"inputs":[],"name":"InvalidSignatureLength","type":"error"},{"inputs":[],"name":"InvalidSigner","type":"error"},{"inputs":[],"name":"LengthMismatch","type":"error"},{"inputs":[{"internalType":"uint256","name":"signatureDeadline","type":"uint256"}],"name":"SignatureExpired","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"token","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint160","name":"amount","type":"uint160"},{"indexed":false,"internalType":"uint48","name":"expiration","type":"uint48"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":false,"internalType":"address","name":"token","type":"address"},{"indexed":false,"internalType":"address","name":"spender","type":"address"}],"name":"Lockdown","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"token","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint48","name":"newNonce","type":"uint48"},{"indexed":false,"internalType":"uint48","name":"oldNonce","type":"uint48"}],"name":"NonceInvalidation","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"token","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint160","name":"amount","type":"uint160"},{"indexed":false,"internalType":"uint48","name":"expiration","type":"uint48"},{"indexed":false,"internalType":"uint48","name":"nonce","type":"uint48"}],"name":"Permit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":false,"internalType":"uint256","name":"word","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"mask","type":"uint256"}],"name":"UnorderedNonceInvalidation","type":"event"},{"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint160","name":"amount","type":"uint160"},{"internalType":"uint48","name":"expiration","type":"uint48"},{"internalType":"uint48","name":"nonce","type":"uint48"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint160","name":"amount","type":"uint160"},{"internalType":"uint48","name":"expiration","type":"uint48"}],"name":"approve","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint48","name":"newNonce","type":"uint48"}],"name":"invalidateNonces","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"wordPos","type":"uint256"},{"internalType":"uint256","name":"mask","type":"uint256"}],"name":"invalidateUnorderedNonces","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"internalType":"address","name":"token","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"internalType":"struct IAllowanceTransfer.TokenSpenderPair[]","name":"approvals","type":"tuple[]"}],"name":"lockdown","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"nonceBitmap","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"components":[{"components":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint160","name":"amount","type":"uint160"},{"internalType":"uint48","name":"expiration","type":"uint48"},{"internalType":"uint48","name":"nonce","type":"uint48"}],"internalType":"struct IAllowanceTransfer.PermitDetails[]","name":"details","type":"tuple[]"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"sigDeadline","type":"uint256"}],"internalType":"struct IAllowanceTransfer.PermitBatch","name":"permitBatch","type":"tuple"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"permit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"components":[{"components":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint160","name":"amount","type":"uint160"},{"internalType":"uint48","name":"expiration","type":"uint48"},{"internalType":"uint48","name":"nonce","type":"uint48"}],"internalType":"struct IAllowanceTransfer.PermitDetails","name":"details","type":"tuple"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"sigDeadline","type":"uint256"}],"internalType":"struct IAllowanceTransfer.PermitSingle","name":"permitSingle","type":"tuple"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"permit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"components":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"internalType":"struct ISignatureTransfer.TokenPermissions","name":"permitted","type":"tuple"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"internalType":"struct ISignatureTransfer.PermitTransferFrom","name":"permit","type":"tuple"},{"components":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"requestedAmount","type":"uint256"}],"internalType":"struct ISignatureTransfer.SignatureTransferDetails","name":"transferDetails","type":"tuple"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"permitTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"components":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"internalType":"struct ISignatureTransfer.TokenPermissions[]","name":"permitted","type":"tuple[]"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"internalType":"struct ISignatureTransfer.PermitBatchTransferFrom","name":"permit","type":"tuple"},{"components":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"requestedAmount","type":"uint256"}],"internalType":"struct ISignatureTransfer.SignatureTransferDetails[]","name":"transferDetails","type":"tuple[]"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"permitTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"components":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"internalType":"struct ISignatureTransfer.TokenPermissions","name":"permitted","type":"tuple"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"internalType":"struct ISignatureTransfer.PermitTransferFrom","name":"permit","type":"tuple"},{"components":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"requestedAmount","type":"uint256"}],"internalType":"struct ISignatureTransfer.SignatureTransferDetails","name":"transferDetails","type":"tuple"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"bytes32","name":"witness","type":"bytes32"},{"internalType":"string","name":"witnessTypeString","type":"string"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"permitWitnessTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"components":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"internalType":"struct ISignatureTransfer.TokenPermissions[]","name":"permitted","type":"tuple[]"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"internalType":"struct ISignatureTransfer.PermitBatchTransferFrom","name":"permit","type":"tuple"},{"components":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"requestedAmount","type":"uint256"}],"internalType":"struct ISignatureTransfer.SignatureTransferDetails[]","name":"transferDetails","type":"tuple[]"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"bytes32","name":"witness","type":"bytes32"},{"internalType":"string","name":"witnessTypeString","type":"string"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"permitWitnessTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint160","name":"amount","type":"uint160"},{"internalType":"address","name":"token","type":"address"}],"internalType":"struct IAllowanceTransfer.AllowanceTransferDetails[]","name":"transferDetails","type":"tuple[]"}],"name":"transferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint160","name":"amount","type":"uint160"},{"internalType":"address","name":"token","type":"address"}],"name":"transferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"}]
"#;

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
        version: "1",
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



sol! {
    #[derive(Debug)]
    struct ExactInSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMin;
    }

    #[derive(Debug)]
    struct PoolKey {
        address currency0;
        address currency1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }
}

fn make_pool_key(
    token_a: Address,
    token_b: Address,
    fee: u32,
    tick_spacing: i32,
    hooks: Address,
) -> (Address, Address, U24, i32, Address) {
    let a_bytes = token_a.0;
    let b_bytes = token_b.0;

    if a_bytes < b_bytes {
        (token_a, token_b, U24::from(fee), tick_spacing, hooks)
    } else {
        (token_b, token_a, U24::from(fee), tick_spacing, hooks)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    // Load WebSocket RPC URL and private key from environment
    let ws_url = env::var("ETH_WS_RPC_URL")
        .unwrap_or_else(|_| "wss://eth.llamarpc.com".to_string());
    let private_key = env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY must be set in environment");

    // Build provider with recommended fillers and local signer
    let signer = PrivateKeySigner::from_slice(&hex::decode(private_key.strip_prefix("0x").unwrap_or(&private_key))?)?;
    let provider = ProviderBuilder::new()
        .wallet(signer.clone())
        .connect(&ws_url)
        .await?;

    // Parse ABIs
    let universal_router_abi: JsonAbi = serde_json::from_str(UNIVERSAL_ROUTER_ABI)?;
    let universal_router: ContractInstance<_, Interface> = ContractInstance::new(
        UNIVERSAL_ROUTER_V4,
        provider.clone(),
        Interface::new(universal_router_abi),
    );
    println!("Universal Router contract initialized at: {UNIVERSAL_ROUTER_V4}");

    // --- Manual Approve USDC for Permit2 ---
    // let usdc_token = IERC20::new(USDC, provider.clone());
    // let approve_receipt = usdc_token
    //     .approve(PERMIT2_CONTRACT, U256::MAX)
    //     .send()
    //     .await?
    //     .watch()
    //     .await?;
    // println!("Permit2 approved for USDC in tx: {approve_receipt:?}");

    // --- Create and sign the PermitSingle message ---
    let owner_address = signer.address();
    let current_block = provider.get_block(alloy::eips::BlockId::Number(BlockNumberOrTag::Latest)).await?
        .ok_or_else(|| eyre::eyre!("No latest block"))?;
    let current_ts: u64 = current_block.header.timestamp;
    let deadline = U256::from(current_ts + 3000000);
    let sig_deadline = deadline;
    let amount_to_move = U256::from(10_000_000u64);

    let (permit_single, hash) = create_permit2_signable_message(
        USDC,
        amount_to_move,
        current_ts + 3600, // expiration (1 hour from now)
        0,                 // nonce (simple example)
        UNIVERSAL_ROUTER_V4,
        sig_deadline,
        11155111,
        PERMIT2_CONTRACT,
    )?;

    let signature = signer.sign_hash(&hash).await?;
    let signature_bytes: Bytes = signature.as_bytes().to_vec().into();
    println!("PermitSingle signed. Signature: {:?}", signature_bytes);

    // --- Build the Universal Router execute call with PERMIT2_PERMIT and V4_SWAP commands ---

    // Commands: PERMIT2_PERMIT (0x0a) and V4_SWAP (0x10)
    let commands = DynSolValue::Bytes(vec![0x0a, 0x10]);

    // 1. Build PERMIT2_PERMIT input
    // This input is a tuple of (PermitSingle, bytes signature)
    let permit_input = DynSolValue::Tuple(vec![
        DynSolValue::Tuple(vec![
            DynSolValue::Tuple(vec![
                DynSolValue::Address(permit_single.details.token),
                DynSolValue::Uint(U256::from(permit_single.details.amount.as_limbs()[0]), 160),
                DynSolValue::Uint(U256::from(permit_single.details.expiration.as_limbs()[0]), 48),
                DynSolValue::Uint(U256::from(permit_single.details.nonce.as_limbs()[0]), 48),
            ]),
            DynSolValue::Address(permit_single.spender),
            DynSolValue::Uint(permit_single.sigDeadline, 256),
        ]),
        DynSolValue::Bytes(signature_bytes.to_vec()),
    ]);

    // 2. Build V4_SWAP input
    let zero_for_one = USDC < LINK;
    let fee = U24::from(3000u32);

    // V4_SWAP input is a tuple of (bytes actions, bytes[] arguments)
    let v4_actions_bytes: Bytes = vec![
        0x06u8, // SWAP_EXACT_IN_SINGLE
        0x0cu8, // SETTLE_ALL
        0x0fu8, // TAKE_ALL
    ].into();

let token_in = USDC;
let token_out = LINK;
let fee_u32 = 3000u32;
let tick_spacing_i32 = 60; // <-- set correct tick spacing for the pool/fee tier
let hooks_addr = Address::ZERO;

let (currency0, currency1, fee_u24, tick_spacing, hooks) =
    make_pool_key(token_in, token_out, fee_u32, tick_spacing_i32, hooks_addr);

// Convert amounts to u128 safely
let amount_in_u128: u128 = amount_to_move
    .try_into()
    .map_err(|_| eyre::eyre!("amount_in doesn't fit into u128"))?;
let amount_out_min_u128: u128 = 0u128;

// hookData (empty for now)
let hook_data: Vec<u8> = vec![];

// Build the nested tuple for PoolKey
let poolkey_tuple = DynSolValue::Tuple(vec![
    DynSolValue::Address(currency0),
    DynSolValue::Address(currency1),
    // fee is uint24 => represent using U256 of the value but indicate 24 bits in DynSolValue::Uint
    DynSolValue::Uint(U256::from(fee_u24.to::<u32>()), 24),
    // tickSpacing is int24, but DynSolValue doesn't directly have signed ints —
    // encode two's complement into 24 bits using U256 representation
    {
        // convert signed i32 to i128 then to two's complement 24-bit representation as U256
        let ts = tick_spacing as i128;
        let ts_u256 = if ts < 0 {
            // compute two's complement for 24 bits
            let mask = (1u128 << 24) - 1;
            let ts_twos = (!((-ts) as u128) + 1u128) & mask;
            U256::from(ts_twos)
        } else {
            U256::from(ts as u64)
        };
        DynSolValue::Uint(ts_u256, 24)
    },
    DynSolValue::Address(hooks),
]);

// Build the ExactInSingleParamsV4 tuple:
// (PoolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMin, bytes hookData)
let exact_in_tuple = DynSolValue::Tuple(vec![
    poolkey_tuple,
    DynSolValue::Bool(zero_for_one),
    DynSolValue::Uint(U256::from(amount_in_u128), 128),
    DynSolValue::Uint(U256::from(amount_out_min_u128), 128),
    DynSolValue::Bytes(hook_data),
]);

    let encoded_swap = exact_in_tuple.abi_encode();

    let encoded_settle = SettleAllParams {
        token: USDC,
        amount: amount_to_move,
    }.abi_encode();

    let encoded_take = TakeAllParams {
        token: LINK,
        minAmount: U256::from(0),
    }.abi_encode();

    let v4_arguments = DynSolValue::Array(vec![
        DynSolValue::Bytes(encoded_swap),
        DynSolValue::Bytes(encoded_settle),
        DynSolValue::Bytes(encoded_take),
    ]);

    let encoded_v4_swap_input = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(v4_actions_bytes.to_vec()),
        v4_arguments,
    ]).abi_encode();

    // 3. Create the final inputs vector for `execute`
    let inputs_vec: Vec<DynSolValue> = vec![
        DynSolValue::Bytes(permit_input.abi_encode()),
        DynSolValue::Bytes(encoded_v4_swap_input),
    ];

    // Find execute(bytes,bytes[],uint256) and encode calldata
    let function = universal_router
        .abi()
        .functions()
        .find(|f| f.name == "execute" && f.inputs.len() == 3)
        .expect("Function not found");

    let calldata = function.abi_encode_input(&[
        commands,
        DynSolValue::Array(inputs_vec),
        DynSolValue::Uint(deadline, 256),
    ])?;

    let tx = TransactionRequest {
        to: Some(TxKind::Call(UNIVERSAL_ROUTER_V4)),
        input: calldata.into(),
        ..Default::default()
    };

    println!("Sending transaction with Permit2 Permit and V4 Swap...");
    let pending_tx = provider.send_transaction(tx).await?;
    let receipt = pending_tx.watch().await?;
    println!("Transaction mined: {:?}", receipt);

    Ok(())
}