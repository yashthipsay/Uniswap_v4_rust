from web3 import Web3
from eth_account import Account
from abis.load_abis import load_abis
import logging
import os
import time
from uniswap_universal_router_decoder.router_codec import RouterCodec
from web3.types import Wei
from eth_abi import encode as abi_encode
from typing import Any, Dict, Optional, Union
from gq_oems_py.services.adapters.adapter import ExchangeAdapter
import asyncio
from datetime import datetime, timedelta
from collections import deque
import random
import math
import aiohttp
import httpx
import json
logger = logging.getLogger(__name__)

RPC_URL = 'https://sepolia.infura.io/v3/a6cd886ad67c44bdb86bb5ab0797f5b4'

class UniswapV4Adapter(ExchangeAdapter):
    def __init__(
        self,
        rpc_urls: Union[str, list],
        private_key: str = None,
    ):
        # Initialize only essential connection parameters
        self.rpc_url = rpc_urls
        self.private_key = private_key
        self.authenticated = False
        self.web3 = None
        self.account = None
        self.wallet_address = None
        self.limit_orders = {}  
        self.monitor_tasks = {} 
                
        # Order queue and RPC management
        self.order_queue = asyncio.Queue()
        self.worker_tasks = []
        self.num_workers = 5
        self.current_rpc_index = 0
        self.rpc_instances = []
        self.queue_processor_task = None
        self.exchange = self
        self.exchange_name = "uniswap_v4"
        self.nonce_lock = asyncio.Lock()
        self.next_nonce = 0
        
    def _initialize_contracts_and_services(self, web3_instance: Web3) -> bool:
        """Helper method to initialize contracts and services with a given web3 instance."""
        try:
            self.universal_router = web3_instance.eth.contract(
                address=Web3.to_checksum_address(self.contract_addresses["universal_router"]),
                abi=self.abis["universal_router"]
            )
            self.permit2 = web3_instance.eth.contract(
                address=Web3.to_checksum_address(self.contract_addresses["permit2"]),
                abi=self.abis["permit2"]
            )
            self.pool_manager = web3_instance.eth.contract(
                address=Web3.to_checksum_address(self.contract_addresses["pool_manager"]),
                abi=self.abis["pool_manager"]
            )
            self.state_view = web3_instance.eth.contract(
                address=Web3.to_checksum_address(self.contract_addresses["state_view"]),
                abi=self.abis["state_view"]
            )
            self.quoterv4 = web3_instance.eth.contract(
                address=Web3.to_checksum_address(self.contract_addresses["quoterv4"]),
                abi=self.abis["quoter"]  # Uses "quoter" ABI as per your original initialize
            )
            # Initialize router codec
            self.router_codec = RouterCodec(w3=web3_instance)
            
        
            logger.debug(f"Re-initialized contracts and services with RPC: {getattr(web3_instance.provider, 'endpoint_uri', 'N/A')}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize/re-initialize contracts and services: {e}", exc_info=True)
            return False
        
    async def reset_nonce(self):
        async with self.nonce_lock:
            self.next_nonce = await asyncio.to_thread(
                self.web3.eth.get_transaction_count, self.wallet_address, 'pending'
            )
            logger.info(f"Nonce reset to {self.next_nonce} for wallet {self.wallet_address}")

    async def initialize(self, account_name: str, is_testnet: bool = False) -> bool:
        """Initialize Uniswap V4 connection"""
        try:
            self.account_name = account_name
            self.is_testnet = is_testnet
            self.chain_id = 11155111  # Sepolia testnet

            # Initialize Web3 connections for all RPCs
            self.rpc_instances = []
            for rpc_url in self.rpc_url:
                web3 = Web3(Web3.HTTPProvider(rpc_url))
                if not web3.is_connected():
                    logger.error(f"Failed to connect to Ethereum node at {rpc_url}")
                    continue
                self.rpc_instances.append(web3)
                
            if not self.rpc_instances:
                logger.error("No valid RPC URLs provided")
                return False
            
            # Use the first available RPC instance
            self.web3 = self.rpc_instances[0]

            # Set up account from private key
            if not self.private_key:
                logger.error("No private key provided")
                return False

            self.account = Account.from_key(self.private_key)
            self.wallet_address = self.account.address


##################################TEST SETUP FOR UNISWAP V4###################################################3
            # Set contract addresses
            self.contract_addresses = {
                "universal_router": '0x3a9d48ab9751398bbfa63ad67599bb04e4bdf98b',
                "permit2": '0x000000000022D473030F116dDEE9F6B43aC78BA3',
                "pool_manager": '0xE03A1074c86CFeDd5C142C4F04F1a1536e203543',
                "state_view": '0xE1Dd9c3fA50EDB962E442f60DfBc432e24537E4C',
                "quoterv4": '0x61b3f2011a92d183c7dbadbda940a7555ccf9227'
            }

            # Set token addresses 
            self.token_addresses = {
                "USDC": '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',
                "LINK": '0x779877A7B0D9E8603169DdbD7836e478b4624789',
                "UNI": '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',
                "ETH": '0x0000000000000000000000000000000000000000',
                "WETH": '0xdd13E55209Fd76AfE204dBda4007C227904f0a81',  
                "TWETH": "0xfff9976782d46cc05630d1f6ebab18b2324d6b14",
                "BYT": "0x7352cdbca63f62358f08f6514d3b7ff2a2872aad",       
            }
            
################################################################################################################



###################################MAINNET SETUP FOR UNISWAP V4###################################################
            # self.contract_addresses = {
            #     "universal_router": '0x66a9893cc07d91d95644aedd05d03f95e1dba8af',
            #     "permit2": '0x000000000022D473030F116dDEE9F6B43aC78BA3',
            #     "pool_manager": '0x000000000004444c5dc75cB358380D2e3dE08A90',
            #     "state_view": '0x7ffe42c4a5deea5b0fec41c94c136cf115597227',
            #     "quoterv4": '0x52f0e24d1c21c8a0cb1e5a5dd6198556bd9e1203'
            # }

            self.mainnet_token_addresses = {
                "WBTC": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
                "USDC": '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
                "DAI": '0x6B175474E89094C44Da98b954EedeAC495271d0F',
                "LINK": '0x514910771AF9Ca656af840dff83E8264EcF986CA',
                "UNI": '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',
                "ETH": '0x0000000000000000000000000000000000000000',
                "WETH": '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'  # Correct mainnet WETH address
            }
            
#################################################################################################################

            # Set ABIs directory and load ABIs
            self.abis_dir = os.path.join(os.path.dirname(__file__), 'abis')
            try:
                self.abis = load_abis(self.abis_dir)
                self.erc20_abi = self.abis["erc20"]  # Add this line
            except Exception as e:
                logger.error(f"Failed to load ABIs: {e}")
                return False

            # # Initialize contract instances
            # try:
            #     self.universal_router = self.web3.eth.contract(
            #         address=Web3.to_checksum_address(self.contract_addresses["universal_router"]),
            #         abi=self.abis["universal_router"]
            #     )
            #     self.permit2 = self.web3.eth.contract(
            #         address=Web3.to_checksum_address(self.contract_addresses["permit2"]),
            #         abi=self.abis["permit2"]
            #     )
            #     self.pool_manager = self.web3.eth.contract(
            #         address=Web3.to_checksum_address(self.contract_addresses["pool_manager"]),
            #         abi=self.abis["pool_manager"]
            #     )
            #     self.state_view = self.web3.eth.contract(
            #         address=Web3.to_checksum_address(self.contract_addresses["state_view"]),
            #         abi=self.abis["state_view"]
            #     )
            #     # Get quotes for standard amounts
            #     self.quoterv4 = self.web3.eth.contract(
            #         address=Web3.to_checksum_address(self.contract_addresses["quoterv4"]),
            #         abi=self.abis["quoter"]
            #     )
            # except Exception as e:
            #     logger.error(f"Failed to initialize contracts: {e}")
            #     return False

            # Initialize router codec
            # self.router_codec = RouterCodec(w3=self.web3)
            
            # Initialize contract instances and services
            if not self._initialize_contracts_and_services(self.web3):
                logger.error("Failed to initialize contract instances and services")
                return False
            
            # Reset nonce using the reset_nonce function
            await self.reset_nonce()
            
            # Mark as authenticated
            self.authenticated = True
            
            for i in range(self.num_workers):
                for i in range(self.num_workers):
                    task = asyncio.create_task(self._process_order_queue(i))
                    self.worker_tasks.append(task)
            
            logger.info(f"Successfully initialized Uniswap V4 connection for {account_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize Uniswap V4: {str(e)}")
            self.authenticated = False
            return False
        
    ################################### MESSAGING QUEUE LOGIC #####################################
    def get_next_rpc(self):
        """Round-robin RPC selection"""
        if not self.rpc_instances:
            return None
        
        self.current_rpc_index = (self.current_rpc_index + 1) % len(self.rpc_instances)
        return self.rpc_instances[self.current_rpc_index]
    
    async def _process_order_queue(self, worker_id: int):
        """Background task to process orders from the queue"""
        while True:
            if not self.order_queue.empty():
                order = await self.order_queue.get()
                try:
                    # Get next available rpc
                    # rpc = self.get_next_rpc()
                    # if not rpc:
                    #     logger.error("No available RPCs to process the order")
                    #     await asyncio.sleep(1)
                    #     continue
                    
                    # # Log the RPC being used
                    # endpoint = getattr(rpc.provider, "endpoint_uri", None)
                    # logger.info(f"[Worker {worker_id}] Using RPC endpoint: {endpoint}")
                    
                    # # Temporarily switch to this RPC
                    # current_web3 = self.web3
                    # self.web3 = rpc
                    
                    # # Reinitialize contracts and services with the new RPC
                    # logger.info(f"[Worker {worker_id}] Reinitializing contracts and services with new RPC")
                    # if not self._initialize_contracts_and_services(self.web3):
                    #     logger.error(f"[Worker {worker_id}] Failed to reinitialize contracts with new RPC")
                    #     self.web3 = current_web3
                    
                    # Use the same RPC without reinitializing the contracts again
                    current_web3 = self.web3
                    
                    if order["type"] == 'market':
                        result = await self._execute_market_order(
                            symbol=order['symbol'],
                            side=order['side'],
                            quantity=order['quantity'],
                            client_algo_id=order['client_algo_id']                            
                        )
                    elif order['type'] == 'limit':
                        result = await self._execute_limit_order(
                            symbol=order['symbol'],
                            side=order['side'],
                            quantity=order['quantity'],
                            price=order['price'],
                            client_algo_id=order['client_algo_id']
                        )
                    elif order['type'] == 'market_edge':
                        result = await self._execute_market_edge_order(
                            symbol=order['symbol'],
                            side=order['side'],
                            quantity=order['quantity'],
                            duration=order['duration'],
                            client_algo_id=order['client_algo_id']
                        )        
                    elif order['type'] == 'limit_edge':
                        result = await self._execute_limit_edge_order(
                            symbol=order['symbol'],
                            side=order['side'],
                            quantity=order['quantity'],
                            duration=order['duration'],
                            client_algo_id=order['client_algo_id'],
                            base_token=order['base_token'],
                            quote_token=order['quote_token']
                        )   
                    elif order["type"] == "ioc":
                        # IOC order processing
                        symbol = order["symbol"]
                        side = order["side"]
                        quantity = order["quantity"]
                        slippage = order["price"]  # Slippage tolerance
                        client_algo_id = order["client_algo_id"]
                        
                        # Broadcast algo status and order update status
                        

                        try:
                            # Parse symbol and get token addresses
                            token_symbols = symbol.split('/')
                            if len(token_symbols) != 2:
                                result = {
                                    "status": "error",
                                    "message": f"Invalid symbol format: {symbol}. Expected format: TOKEN1/TOKEN2",
                                    "client_algo_id": client_algo_id
                                }
                                if "callback" in order:
                                    order["callback"](result)
                                continue

                            base_token, quote_token = token_symbols[0], token_symbols[1]
                            if base_token not in self.token_addresses or quote_token not in self.token_addresses:
                                result = {
                                    "status": "error",
                                    "message": f"Unsupported tokens: {base_token} or {quote_token}",
                                    "client_algo_id": client_algo_id
                                }
                                if "callback" in order:
                                    order["callback"](result)
                                continue

                            base_token_address = self.token_addresses[base_token]
                            quote_token_address = self.token_addresses[quote_token]

                            # Get spot price
                            price_info = await self._fetch_current_price(symbol)
                            if not price_info:
                                result = {
                                    "status": "error",
                                    "message": f"Failed to fetch price for {symbol}",
                                    "client_algo_id": client_algo_id,
                                    "executed_amount_in": 0.0,
                                    "canceled_amount_in": quantity
                                }
                                if "callback" in order:
                                    order["callback"](result)
                                continue

                            spot_price = float(price_info["price_data"]["spot_price"])

                            # Helper function to get quote for a given quantity
                            async def get_quote(amount_in: float) -> tuple[float, float]:
                                try:
                                    quote_info = await self._fetch_current_price(symbol, target_amount=amount_in)
                                    if not quote_info or not quote_info.get("target_quote"):
                                        return 0.0, 0.0
                                    quote = quote_info["target_quote"]
                                    amount_out = quote["amount_out"]
                                    quoted_price = quote["price"]
                                    return amount_out, quoted_price
                                except Exception as e:
                                    logger.error(f"Failed to get quote for {amount_in}: {e}")
                                    return 0.0, 0.0

                            # Check if full quantity is executable
                            amount_out, quoted_price = await get_quote(quantity)
                            print(f"SPOT PRICE: {spot_price}, QUOTED PRICE: {quoted_price}, AMOUNT OUT: {amount_out}")
                            slippage_actual = abs((quoted_price - spot_price) / spot_price) if quoted_price > 0 else float('inf')
                            slippage_actual_pct = slippage_actual * 100
                            logger.info(f"Desired Slippage: {slippage}, Actual Slippage: {slippage_actual_pct}")

                            if slippage_actual_pct <= slippage:
                                executable_quantity = quantity
                            else:
                                # Binary search for maximum executable quantity
                                low, high = 0.0, quantity
                                precision = 0.01  # Stop when range is smaller than 0.001 units
                                executable_quantity = 0.0

                                while high - low > precision:
                                    mid = (low + high) / 2
                                    amount_out, quoted_price = await get_quote(mid)
                                    slippage_actual = abs((quoted_price - spot_price) / spot_price) if quoted_price > 0 else float('inf')
                                    slippage_actual_pct = slippage_actual * 100

                                    if slippage_actual_pct <= slippage:
                                        executable_quantity = mid
                                        low = mid
                                    else:
                                        high = mid

                            if executable_quantity < 0.0001:  # Minimum threshold to avoid negligible trades
                                result = {
                                    "status": "error",
                                    "message": f"No quantity can be executed within {slippage*100}% slippage",
                                    "client_algo_id": client_algo_id,
                                    "executed_amount_in": 0.0,
                                    "canceled_amount_in": quantity
                                }
                                if "callback" in order:
                                    order["callback"](result)
                                continue

                            # Execute the swap using _execute_market_order
                            canceled_quantity = quantity - executable_quantity
                            if executable_quantity > 0:
                                swap_result = await self.place_market_algo(
                                    symbol=symbol,
                                    side=side,
                                    quantity=executable_quantity,
                                    client_algo_id=client_algo_id,
                                )
                                if swap_result.get("status") == "success":
                                    result = {
                                        "status": "success",
                                        "message": "Swap executed successfully",
                                        "client_algo_id": client_algo_id,
                                        "executed_amount_in": executable_quantity,
                                        "canceled_amount_in": canceled_quantity,
                                        "slippage": slippage
                                    }
                                else:
                                    result = {
                                        "status": "error",
                                        "message": f"Failed to execute swap: {swap_result.get('message')}",
                                        "client_algo_id": client_algo_id,
                                        "executed_amount_in": 0.0,
                                        "canceled_amount_in": quantity,
                                        "slippage": slippage
                                    }
                            else:
                                result = {
                                    "status": "error",
                                    "message": "No quantity executed within slippage tolerance",
                                    "client_algo_id": client_algo_id,
                                    "executed_amount_in": 0.0,
                                    "canceled_amount_in": quantity,
                                    "slippage": slippage
                                }

                            logger.info(f"IOC Order {client_algo_id}: Executed {executable_quantity}, Canceled {canceled_quantity}")

                        except Exception as e:
                            error_msg = f"Failed to process IOC order: {str(e)}"
                            logger.error(error_msg)
                            result = {
                                "status": "error",
                                "message": error_msg,
                                "client_algo_id": client_algo_id,
                                "executed_amount_in": 0.0,
                                "canceled_amount_in": quantity,
                                "slippage": slippage
                            }                 
                    # Restore original RPC
                    # self.web3 = current_web3
                    
                    # Store result if callback provided
                    if 'callback' in order:
                        order['callback'](result)
                        
                except Exception as e:
                    logger.error(f"Failed to process order: {str(e)}")
                    # Put failed order back in queue for retry
                    self.order_queue.put(order)
                    await asyncio.sleep(5)
            else:
                await asyncio.sleep(0.1)  
                
    def generate_algo_params(self, client_algo_id: str) -> Dict[str, Any]:
        """
        Generate algorithm parameters with unique client order ID
        
        Args:
            client_algo_id: The base client algorithm ID
            
        Returns:
            Dictionary with clientOrderId and other parameters
        """
        import uuid
        unique_suffix = uuid.uuid4().hex[:4]
        client_order_id = f"{client_algo_id}{unique_suffix}"
        logger.info(f"Using client order id: {client_order_id}")
        return {
            "clientOrderId": client_order_id,
        }             

    async def get_status(self) -> dict:
        """Get exchange connection status"""
        return {
            "connected": self.web3.is_connected() if self.web3 else False,
            "authenticated": self.authenticated,
            "account": self.account_name,
            "wallet": self.wallet_address,
            "chain_id": self.chain_id
        }
        
    def get_token_contract(self, token_address):
        return self.web3.eth.contract(
            address=Web3.to_checksum_address(token_address),
            abi=self.erc20_abi
        )
        
    def approve_token_with_permit2(self, token_address, amount, expiration):
        try:
            token = self.get_token_contract(token_address)
            base_nonce = self.web3.eth.get_transaction_count(self.wallet_address)
            max_amount = 2**256 - 1
            permit2_approval_tx = token.functions.approve(
                Web3.to_checksum_address(self.contract_addresses["permit2"]),
                max_amount
            ).build_transaction({
                'from': self.wallet_address,
                'nonce': base_nonce,
                'gas': 100000,
                'gasPrice': self.web3.to_wei('50', 'gwei'),
                'chainId': self.chain_id
            })
            signed_tx = self.web3.eth.account.sign_transaction(permit2_approval_tx, self.account.key)
            permit2_tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            self.web3.eth.wait_for_transaction_receipt(permit2_tx_hash)

            router_approval_tx = self.permit2.functions.approve(
                Web3.to_checksum_address(token_address),
                Web3.to_checksum_address(self.contract_addresses["universal_router"]),
                amount,
                expiration
            ).build_transaction({
                'from': self.wallet_address,
                'nonce': self.web3.eth.get_transaction_count(self.wallet_address),
                'gas': 100000,
                'gasPrice': self.web3.to_wei('50', 'gwei'),
                'chainId': self.chain_id
            })
            signed_tx = self.web3.eth.account.sign_transaction(router_approval_tx, self.account.key)
            router_tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            self.web3.eth.wait_for_transaction_receipt(router_tx_hash)
            return permit2_tx_hash.hex(), router_tx_hash.hex()
        except Exception as e:
            print(f"Error during token approval: {e}")
            raise
        
    def create_permit_signature(self, token_address, amount=None, expiration=None, deadline=None):
        try:
            token_address = Web3.to_checksum_address(token_address)
            router_address = Web3.to_checksum_address(self.contract_addresses["universal_router"])
            permit2_address = Web3.to_checksum_address(self.contract_addresses["permit2"])
            p2_amount, p2_expiration, p2_nonce = self.router_codec.fetch_permit2_allowance(
                wallet=self.wallet_address,
                token=token_address,
                spender=router_address,
                permit2=permit2_address,
                permit2_abi=self.abis["permit2"]
            )
            if expiration is None:
                expiration = self.router_codec.get_default_expiration()
            if deadline is None:
                deadline = self.router_codec.get_default_deadline()
            if amount is None:
                amount = 2**160 - 1
            permit_data, signable_message = self.router_codec.create_permit2_signable_message(
                token_address=token_address,
                amount=amount,
                expiration=expiration,
                nonce=p2_nonce,
                spender=router_address,
                deadline=deadline,
                chain_id=self.chain_id,
                verifying_contract=permit2_address
            )
            signed_message = self.account.sign_message(signable_message)
            return permit_data, signed_message
        except Exception as e:
            print(f"Error creating permit signature: {e}")
            raise
        
    def create_permit_signature(self, token_address, amount=None, expiration=None, deadline=None):
        try:
            token_address = Web3.to_checksum_address(token_address)
            router_address = Web3.to_checksum_address(self.contract_addresses["universal_router"])
            permit2_address = Web3.to_checksum_address(self.contract_addresses["permit2"])
            p2_amount, p2_expiration, p2_nonce = self.router_codec.fetch_permit2_allowance(
                wallet=self.wallet_address,
                token=token_address,
                spender=router_address,
                permit2=permit2_address,
                permit2_abi=self.abis["permit2"]
            )
            if expiration is None:
                expiration = self.router_codec.get_default_expiration()
            if deadline is None:
                deadline = self.router_codec.get_default_deadline()
            if amount is None:
                amount = 2**160 - 1
            permit_data, signable_message = self.router_codec.create_permit2_signable_message(
                token_address=token_address,
                amount=amount,
                expiration=expiration,
                nonce=p2_nonce,
                spender=router_address,
                deadline=deadline,
                chain_id=self.chain_id,
                verifying_contract=permit2_address
            )
            signed_message = self.account.sign_message(signable_message)
            return permit_data, signed_message
        except Exception as e:
            print(f"Error creating permit signature: {e}")
            raise

    def check_permit2_allowance(self, token_address):
        """
        Check if token has already been approved for Permit2.
        Return: True if sufficient, False if insufficient.
        """
        token_contract = self.web3.eth.contract(
            address=Web3.to_checksum_address(token_address),
            abi=self.erc20_abi
        )
        #Check allowance for Permit2 contract
        permit2_allowance = token_contract.functions.allowance(
            self.wallet_address,
            self.permit2.address
        ).call()
        print(f"Current Permit2 allowance: {permit2_allowance}")
        
        #Consider any value above this as "infinite" approval
        LARGE_APPROVAL_THRESHOLD = 2**200
        return permit2_allowance > LARGE_APPROVAL_THRESHOLD

    async def calculate_gas_parameters(self, estimated_gas_limit=500000):
        try:
            base_fee = (await asyncio.to_thread(self.web3.eth.get_block, "latest"))["baseFeePerGas"]
            priority_fee = await asyncio.to_thread(lambda: self.web3.eth.max_priority_fee)   
            max_fee_per_gas = int(base_fee * 1.2 + priority_fee)
            max_priority_fee_per_gas = priority_fee
            total_gas_wei = estimated_gas_limit * max_fee_per_gas
            balance = await asyncio.to_thread(self.web3.eth.get_balance, self.wallet_address)
            if balance < total_gas_wei:
                print("Insufficient balance for gas")
                return None
            return {
                'gas': estimated_gas_limit,
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee_per_gas
            }
        except Exception as e:
            print(f"Error calculating gas: {e}")
            return None
        
    async def get_token_decimals(self, token_address):
        token_contract = self.web3.eth.contract(
            address=Web3.to_checksum_address(token_address),
            abi=self.erc20_abi
        )
        return await asyncio.to_thread(token_contract.functions.decimals().call)
    
    async def get_next_nonce(self):
        async with self.nonce_lock:
            if self.next_nonce is None: 
                # Fetch from chain only once at startup or after a reset
                self.next_nonce = self.web3.eth.get_transaction_count(self.wallet_address, 'pending')
            nonce = self.next_nonce
            self.next_nonce += 1
            return nonce
    
    async def _get_and_increment_local_nonce(self) -> int:
        """
        Retrieves the current local nonce and increments it.
        This method assumes it's called within a context that holds self.nonce_lock.
        """
        if self.next_nonce is None:
            # Should not happen if initialize() was successful
            logger.error("CRITICAL: self.next_nonce is None. Nonce system not properly initialized. Attempting recovery.")
            try:
                self.next_nonce = await asyncio.to_thread(
                    self.web3.eth.get_transaction_count, self.wallet_address, 'pending'
                )
                logger.info(f"Recovered and initialized local nonce to {self.next_nonce}.")
            except Exception as e:
                logger.error(f"Failed to recover nonce from network: {e}")
                raise RuntimeError("Failed to initialize or recover nonce.") from e
        
        nonce_to_use = self.next_nonce
        self.next_nonce += 1
        logger.debug(f"Using nonce {nonce_to_use}, next local nonce will be {self.next_nonce}")
        return nonce_to_use
    
    async def place_single_swap_in_algo(
        self,
        token_in: str,
        token_out: str,
        amount_in: float,
        amount_out_minimum: float = 0,
        fee: int = 3000,
        tick_spacing: int = 60,
        recipient: Optional[str] = None,
        deadline: Optional[int] = None
    ) -> Dict[str, Any]:
        
        """
    Execute a Uniswap V4 exact input swap.
    
    Args:
        token_in: Address of input token
        token_out: Address of output token
        amount_in: Amount of input tokens to swap
        amount_out_minimum: Minimum amount of output tokens to receive (slippage protection)
        fee: Pool fee in basis points (e.g. 3000 = 0.3%)
        tick_spacing: Tick spacing for the pool
        recipient: Address to receive output tokens (defaults to wallet address)
        deadline: Transaction deadline in seconds
    """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}
                
            if recipient is None:
                recipient = self.wallet_address
                
            # Get decimals for both tokens
            decimals_in = await self.get_token_decimals(token_in)
            decimals_out = await self.get_token_decimals(token_out)
            
            # Convert amounts based on decimals
            amount_in_wei = Web3.to_wei(amount_in, 'ether') // (10 ** (18 - decimals_in))
            amount_out_minimum_wei = Web3.to_wei(amount_out_minimum, 'ether') // (10 ** (18 - decimals_out))
            async with self.nonce_lock:
            # Get permit signature 
                permit_data, signed_message = self.create_permit_signature(token_address=token_in)
                logger.info(f"Permit data: {permit_data}")
                logger.info(f"Signed message: {signed_message.signature.hex()}")

                # Determine token order
                token_in = Web3.to_checksum_address(token_in)
                token_out = Web3.to_checksum_address(token_out)
                zero_for_one = token_in < token_out
                currency_0 = token_in if zero_for_one else token_out
                currency_1 = token_out if zero_for_one else token_in
                hooks = '0x0000000000000000000000000000000000000000'

                pool_key = self.router_codec.encode.v4_pool_key(
                    currency_0=currency_0,
                    currency_1=currency_1,
                    fee=fee,
                    tick_spacing=tick_spacing,
                    hooks=hooks
                )

                is_native_input = token_in.lower() == "0x0000000000000000000000000000000000000000"
                gas_params = await self.calculate_gas_parameters()
                if not gas_params:
                    raise Exception("Failed to calculate gas parameters")

                tx_params = (
                    self.router_codec.encode.chain()
                    .permit2_permit(permit_data, signed_message)
                    .v4_swap()
                    .swap_exact_in_single(
                        pool_key=pool_key,
                        zero_for_one=zero_for_one,
                        amount_in=amount_in_wei,
                        amount_out_min=amount_out_minimum_wei,
                        hook_data=b''
                    )
                    .take_all(
                        token_out,
                        amount_out_minimum_wei
                    )
                    .settle_all(
                        token_in,
                        amount_in_wei
                    )
                    .build_v4_swap()
                    .build_transaction(
                        sender=Web3.to_checksum_address(self.wallet_address),
                        value=Wei(amount_in_wei) if is_native_input else Wei(0),
                        ur_address=Web3.to_checksum_address(self.contract_addresses["universal_router"]),
                        deadline=deadline,
                        trx_speed=None,
                        priority_fee=Wei(gas_params["maxPriorityFeePerGas"]),
                        max_fee_per_gas=Wei(gas_params["maxFeePerGas"]),
                        gas_limit=gas_params["gas"]
                    )
                )


                current_tx_nonce = await self._get_and_increment_local_nonce()
                logger.info(f"Using transaction nonce: {current_tx_nonce}")
                # Add nonce
                # tx_params['nonce'] = self.web3.eth.get_transaction_count(self.wallet_address, 'pending')
                tx_params['nonce'] = current_tx_nonce
                # Simulate transaction
                call_params = {
                    'to': tx_params['to'],
                    'from': tx_params['from'],
                    'data': tx_params['data'],
                    'value': tx_params['value'],
                    'gas': tx_params['gas'],
                    'maxFeePerGas': tx_params['maxFeePerGas'],
                    'maxPriorityFeePerGas': tx_params['maxPriorityFeePerGas'],
                }

                try:
                    logger.info("Simulating transaction with eth_call...")
                    await asyncio.to_thread(self.web3.eth.call, call_params, 'pending')
                    logger.info("Transaction simulation successful!")
                except Exception as call_error:
                    error_msg = f"Simulation failed with error: {str(call_error)}"
                    logger.error(error_msg)
                    return {
                        "status": "error",
                        "message": error_msg
                    }

                # Sign and send
                signed_tx = self.account.sign_transaction(tx_params)
                tx_hash = await asyncio.to_thread(self.web3.eth.send_raw_transaction, signed_tx.rawTransaction)
                logger.info(f"Transaction hash: {tx_hash.hex()}")

                # Wait for receipt
                receipt = await asyncio.to_thread(self.web3.eth.wait_for_transaction_receipt, tx_hash)
                # Convert receipt to a plain dictionary
                receipt = dict(receipt)
            logger.info(f"Transaction receipt: {receipt}")
            if receipt['status'] == 0:
                error_msg = "Transaction failed on-chain (reverted). Check slippage or deadline."
                # logger.error(f"{error_msg} - Hash: {tx_hash.hex()}")
                return {
                    "status": "error",
                    "message": error_msg,
                    "transaction_hash": tx_hash.hex(),
                    "receipt": receipt
                }
            return {
                "status": "success",
                "message": "Swap executed successfully",
                "transaction_hash": tx_hash.hex(),
                "input_token": token_in,
                "output_token": token_out,
                "amount_in": amount_in,
                "amount_out_minimum": amount_out_minimum,
                "receipt": receipt
            }

        except Exception as e:
            error_msg = f"Failed to execute swap: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }
            
    async def place_single_swap_out_algo(
        self,
        token_in: str,
        token_out: str, 
        amount_out: float,
        amount_in_maximum: float = 100.0,
        fee: int = 3000,
        tick_spacing: int = 60,
        recipient: Optional[str] = None,
        deadline: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute a Uniswap V4 exact output swap.
        
        Args:
            token_in: Address of input token
            token_out: Address of output token  
            amount_out: Exact amount of output tokens to receive
            amount_in_maximum: Maximum amount of input tokens to spend (slippage protection)
            fee: Pool fee in basis points (e.g. 3000 = 0.3%)
            tick_spacing: Tick spacing for the pool
            recipient: Address to receive output tokens (defaults to wallet address)
            deadline: Transaction deadline in seconds
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}
                
            if recipient is None:
                recipient = self.wallet_address
                
            # Get decimals for both tokens
            decimals_in = await self.get_token_decimals(token_in)
            decimals_out = await self.get_token_decimals(token_out)
            
            # Convert amounts based on decimals
            amount_out_wei = Web3.to_wei(amount_out, 'ether') // (10 ** (18 - decimals_out))
            amount_in_maximum_wei = Web3.to_wei(amount_in_maximum, 'ether') // (10 ** (18 - decimals_in))
            
            async with self.nonce_lock:
                # Get permit signature
                permit_data, signed_message = self.create_permit_signature(token_address=token_in)
                logger.info(f"Permit data: {permit_data}")
                logger.info(f"Signed message: {signed_message.signature.hex()}")

                # Determine token order
                token_in = Web3.to_checksum_address(token_in)
                token_out = Web3.to_checksum_address(token_out)
                zero_for_one = token_in < token_out
                currency_0 = token_in if zero_for_one else token_out
                currency_1 = token_out if zero_for_one else token_in
                hooks = '0x0000000000000000000000000000000000000000'

                pool_key = self.router_codec.encode.v4_pool_key(
                    currency_0=currency_0,
                    currency_1=currency_1,
                    fee=fee,
                    tick_spacing=tick_spacing,
                    hooks=hooks
                )

                is_native_input = token_in.lower() == "0x0000000000000000000000000000000000000000"
                gas_params = await self.calculate_gas_parameters()
                if not gas_params:
                    raise Exception("Failed to calculate gas parameters")

                tx_params = (
                    self.router_codec.encode.chain()
                    .permit2_permit(permit_data, signed_message)
                    .v4_swap()
                    .swap_exact_out_single(  # Changed from swap_exact_in_single
                        pool_key=pool_key,
                        zero_for_one=zero_for_one,
                        amount_out=amount_out_wei,  # Changed from amount_in
                        amount_in_max=amount_in_maximum_wei,  # Changed from amount_out_min
                        hook_data=b''
                    )
                    .take_all(
                        token_out,
                        amount_out_wei  # Changed to exact amount out
                    )
                    .settle_all(
                        token_in,
                        amount_in_maximum_wei  # Changed to max amount in
                    )
                    .build_v4_swap()
                    .build_transaction(
                        sender=Web3.to_checksum_address(self.wallet_address),
                        value=Wei(amount_out_wei) if is_native_input else Wei(0),
                        ur_address=Web3.to_checksum_address(self.contract_addresses["universal_router"]),
                        deadline=deadline,
                        trx_speed=None,
                        priority_fee=Wei(gas_params["maxPriorityFeePerGas"]),
                        max_fee_per_gas=Wei(gas_params["maxFeePerGas"]),
                        gas_limit=gas_params["gas"]
                    )
                )

                # Add nonce
                # tx_params['nonce'] = self.web3.eth.get_transaction_count(self.wallet_address, 'pending')
                current_tx_nonce = await self._get_and_increment_local_nonce()
                logger.info(f"Using transaction nonce: {current_tx_nonce}")
                # Add nonce
                # tx_params['nonce'] = self.web3.eth.get_transaction_count(self.wallet_address, 'pending')
                tx_params['nonce'] = current_tx_nonce
                # Simulate transaction
                call_params = {
                    'to': tx_params['to'],
                    'from': tx_params['from'],
                    'data': tx_params['data'],
                    'value': tx_params['value'],
                    'gas': tx_params['gas'],
                    'maxFeePerGas': tx_params['maxFeePerGas'],
                    'maxPriorityFeePerGas': tx_params['maxPriorityFeePerGas'],
                }

                try:
                    logger.info("Simulating transaction with eth_call...")
                    self.web3.eth.call(call_params, 'pending')
                    logger.info("Transaction simulation successful!")
                except Exception as call_error:
                    error_msg = f"Simulation failed with error: {str(call_error)}"
                    logger.error(error_msg)
                    return {
                        "status": "error",
                        "message": error_msg
                    }

                # Sign and send
                signed_tx = self.account.sign_transaction(tx_params)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                logger.info(f"Transaction hash: {tx_hash.hex()}")

                # Wait for receipt
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                # Convert receipt to a plain dictionary
                receipt = dict(receipt)
            logger.info(f"Transaction receipt: {receipt}")

            return {
                "status": "success",
                "message": "Swap executed successfully",
                "transaction_hash": tx_hash.hex(),
                "input_token": token_in,
                "output_token": token_out,
                "amount_out": amount_out,
                "amount_in_maximum": amount_in_maximum,
                "receipt": receipt
            }

        except Exception as e:
            error_msg = f"Failed to execute swap: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }
            
    async def place_multihop_swap_in_algo(
        self,
        token_in: str,
        path_tokens: list,
        fees: list,
        tick_spacings: list,
        amount_in: float,
        amount_out_minimum: float = 0,
        recipient: Optional[str] = None,
        deadline: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute a Uniswap V4 multi-hop exact input swap.
        
        Args:
            token_in: Address of input token
            path_tokens: List of token addresses in the swap path
            fees: List of pool fees for each hop
            tick_spacings: List of tick spacings for each hop
            amount_in: Amount of input tokens to swap
            amount_out_minimum: Minimum amount of output tokens to receive
            recipient: Address to receive output tokens (defaults to wallet address)
            deadline: Transaction deadline in seconds
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}
                
            if recipient is None:
                recipient = self.wallet_address
                
            if deadline is None:
                deadline = int(time.time()) + 600  # 10 minutes
                
            # Get decimals for input token
            decimals_in = await self.get_token_decimals(token_in)
            
            # Convert input amount based on decimals
            amount_in_wei = Web3.to_wei(amount_in, 'ether') // (10 ** (18 - decimals_in))
            
            # Convert output minimum if specified
            if amount_out_minimum > 0:
                decimals_out = await self.get_token_decimals(path_tokens[-1])
                amount_out_minimum_wei = Web3.to_wei(amount_out_minimum, 'ether') // (10 ** (18 - decimals_out))
            else:
                amount_out_minimum_wei = 0

            # Check and handle Permit2 allowance
            has_permit2_allowance = self.check_permit2_allowance(token_in)
            if not has_permit2_allowance:
                logger.info("Permit2 approval needed. Initiating approval...")
                try:
                    expiration = int(time.time()) + 3600
                    self.approve_token_with_permit2(token_in, amount_in_wei, expiration)
                except Exception as e:
                    error_msg = f"Failed to get Permit2 approval: {str(e)}"
                    logger.error(error_msg)
                    return {"status": "error", "message": error_msg}
                time.sleep(2)  # Wait for approval to be mined
            
            # Get permit signature
            permit_data, signed_message = self.create_permit_signature(token_address=token_in)
            logger.info(f"Permit data: {permit_data}")
            logger.info(f"Signed message: {signed_message.signature.hex()}")

            # Build path_keys for each hop
            path_keys = []
            for i in range(len(path_tokens) - 1):
                path_keys.append(
                    self.router_codec.encode.v4_path_key(
                        intermediate_currency=path_tokens[i+1],
                        fee=fees[i],
                        tick_spacing=tick_spacings[i],
                        hooks="0x0000000000000000000000000000000000000000"
                    )
                )

            # Get gas parameters
            gas_params = self.calculate_gas_parameters()
            if not gas_params:
                raise Exception("Failed to calculate gas parameters")

            # Build transaction parameters
            tx_params = (
                self.router_codec
                    .encode
                    .chain()
                    .permit2_permit(permit_data, signed_message)
                    .v4_swap()
                    .swap_exact_in(
                        currency_in=Web3.to_checksum_address(token_in),
                        path_keys=path_keys,
                        amount_in=amount_in_wei,
                        amount_out_min=amount_out_minimum_wei,
                    )
                    .take_all(path_tokens[-1], amount_out_minimum_wei)
                    .settle_all(token_in, amount_in_wei)
                    .build_v4_swap()
                    .build_transaction(
                        sender=Web3.to_checksum_address(self.wallet_address),
                        value=Wei(amount_in_wei) if token_in.lower() == "0x0000000000000000000000000000000000000000" else Wei(0),
                        ur_address=Web3.to_checksum_address(self.contract_addresses["universal_router"]),
                        deadline=deadline,
                        trx_speed=None,
                        priority_fee=Wei(gas_params["maxPriorityFeePerGas"]),
                        max_fee_per_gas=Wei(gas_params["maxFeePerGas"]),
                        gas_limit=gas_params["gas"]
                    )
            )

            # Add nonce
            # tx_params['nonce'] = self.web3.eth.get_transaction_count(self.wallet_address, 'pending')
            tx_params['nonce'] = await self.get_next_nonce()
            # Simulate transaction
            call_params = {
                'to': tx_params['to'],
                'from': tx_params['from'],
                'data': tx_params['data'],
                'value': tx_params['value'],
                'gas': tx_params['gas'],
                'maxFeePerGas': tx_params['maxFeePerGas'],
                'maxPriorityFeePerGas': tx_params['maxPriorityFeePerGas'],
            }

            try:
                logger.info("Simulating transaction with eth_call...")
                self.web3.eth.call(call_params, 'pending')
                logger.info("Transaction simulation successful!")
            except Exception as call_error:
                error_msg = f"Simulation failed with error: {str(call_error)}"
                logger.error(error_msg)
                return {
                    "status": "error",
                    "message": error_msg
                }

            # Sign and send
            signed_tx = self.account.sign_transaction(tx_params)
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            logger.info(f"Transaction hash: {tx_hash.hex()}")

            # Wait for receipt
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            logger.info(f"Transaction receipt: {receipt}")

            return {
                "status": "success",
                "message": "Multi-hop swap executed successfully",
                "transaction_hash": tx_hash.hex(),
                "input_token": token_in,
                "path": path_tokens,
                "amount_in": amount_in,
                "amount_out_minimum": amount_out_minimum,
                "receipt": receipt
            }

        except Exception as e:
            error_msg = f"Failed to execute multi-hop swap: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }
            
    async def place_multihop_swap_out_algo(
        self,
        token_in: str,
        path_tokens: list,
        fees: list, 
        tick_spacings: list,
        amount_out: float,
        amount_in_maximum: float = 100.0,
        recipient: Optional[str] = None,
        deadline: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute a Uniswap V4 multi-hop exact output swap.
        
        Args:
            token_in: Address of input token
            path_tokens: List of token addresses in the swap path
            fees: List of pool fees for each hop
            tick_spacings: List of tick spacings for each hop
            amount_out: Exact amount of output tokens to receive
            amount_in_maximum: Maximum amount of input tokens to spend
            recipient: Address to receive output tokens (defaults to wallet address)
            deadline: Transaction deadline in seconds
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}
                
            if recipient is None:
                recipient = self.wallet_address
                
            if deadline is None:
                deadline = int(time.time()) + 600  # 10 minutes
            

            # Get decimals for input and output tokens
            decimals_in = await self.get_token_decimals(token_in)
            decimals_out = await self.get_token_decimals(path_tokens[-1])

            logger.info(f"Out token: {path_tokens[-1]} decimals: {decimals_out}")
            
            # Convert amounts based on decimals
            amount_out_wei = Web3.to_wei(amount_out, 'ether') // (10 ** (18 - decimals_out))
            
            # # If amount_in_maximum not specified, set a high value
            # if amount_in_maximum is None:
            #     amount_in_maximum = amount_out * 2  # Double the output amount as maximum input
            amount_in_maximum = 100.0
            amount_in_maximum_wei = Web3.to_wei(amount_in_maximum, 'ether') // (10 ** (18 - decimals_in))

            # Check and handle Permit2 allowance
            has_permit2_allowance = self.check_permit2_allowance(token_in)
            if not has_permit2_allowance:
                logger.info("Permit2 approval needed. Initiating approval...")
                try:
                    expiration = int(time.time()) + 3600
                    self.approve_token_with_permit2(token_in, amount_in_maximum_wei, expiration)
                except Exception as e:
                    error_msg = f"Failed to get Permit2 approval: {str(e)}"
                    logger.error(error_msg)
                    return {"status": "error", "message": error_msg}
                time.sleep(2)  # Wait for approval to be mined

            # Get permit signature
            permit_data, signed_message = self.create_permit_signature(token_address=token_in)
            logger.info(f"Permit data: {permit_data}")
            logger.info(f"Signed message: {signed_message.signature.hex()}")

            # Build path_keys for each hop
            path_keys = []
            for i in range(len(path_tokens) - 1):
                path_keys.append(
                    self.router_codec.encode.v4_path_key(
                        intermediate_currency=path_tokens[i+1],
                        fee=fees[i],
                        tick_spacing=tick_spacings[i],
                        hooks="0x0000000000000000000000000000000000000000"
                    )
                )

            # Get gas parameters
            gas_params = self.calculate_gas_parameters()
            if not gas_params:
                raise Exception("Failed to calculate gas parameters")

            # Build transaction parameters
            tx_params = (
                self.router_codec
                    .encode
                    .chain()
                    .permit2_permit(permit_data, signed_message)
                    .v4_swap()
                    .swap_exact_out(  
                        currency_out=Web3.to_checksum_address(path_tokens[-1]),
                        path_keys=path_keys,
                        amount_out=amount_out_wei,  # Changed from amount_in
                        amount_in_max=amount_in_maximum_wei,  
                    )
                    .take_all(Web3.to_checksum_address(path_tokens[-1]), amount_out_wei)
                    .settle_all(Web3.to_checksum_address(token_in), amount_in_maximum_wei)
                    .build_v4_swap()
                    .build_transaction(
                        sender=Web3.to_checksum_address(self.wallet_address),
                        value=Wei(amount_in_maximum_wei) if token_in.lower() == "0x0000000000000000000000000000000000000000" else Wei(0),
                        ur_address=Web3.to_checksum_address(self.contract_addresses["universal_router"]),
                        trx_speed=None,
                        priority_fee=Wei(gas_params["maxPriorityFeePerGas"]),
                        max_fee_per_gas=Wei(gas_params["maxFeePerGas"]),
                        gas_limit=gas_params["gas"]
                    )
            )

            # Add nonce
            # tx_params['nonce'] = self.web3.eth.get_transaction_count(self.wallet_address, 'pending')
            tx_params['nonce'] = await self.get_next_nonce()
            # Simulate transaction
            call_params = {
                'to': tx_params['to'],
                'from': tx_params['from'],
                'data': tx_params['data'],
                'value': tx_params['value'],
                'gas': tx_params['gas'],
                'maxFeePerGas': tx_params['maxFeePerGas'],
                'maxPriorityFeePerGas': tx_params['maxPriorityFeePerGas'],
            }

            try:
                logger.info("Simulating transaction with eth_call...")
                self.web3.eth.call(call_params, 'pending')
                logger.info("Transaction simulation successful!")
            except Exception as call_error:
                error_msg = f"Simulation failed with error: {str(call_error)}"
                logger.error(error_msg)
                return {
                    "status": "error",
                    "message": error_msg
                }

            # Sign and send
            signed_tx = self.account.sign_transaction(tx_params)
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            logger.info(f"Transaction hash: {tx_hash.hex()}")

            # Wait for receipt
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            logger.info(f"Transaction receipt: {receipt}")

            return {
                "status": "success",
                "message": "Multi-hop swap executed successfully",
                "transaction_hash": tx_hash.hex(),
                "input_token": token_in,
                "path": path_tokens,
                "amount_out": amount_out,
                "amount_in_maximum": amount_in_maximum,
                "receipt": receipt
            }

        except Exception as e:
            error_msg = f"Failed to execute multi-hop swap: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }
            
    async def _fetch_current_price(self, symbol: str, target_amount: float = None) -> Optional[Dict[str, Any]]:
        """
        Fetch both current spot price and quotes for a given trading pair.
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2" (e.g., "WETH/USDC")
            target_amount: Optional specific amount to get quote for (in base token)
                
        Returns:
            Dictionary containing spot price and quotes information
        """
        try:
            base_symbol, quote_symbol = symbol.upper().split('/')
            base = Web3.to_checksum_address(self.token_addresses[base_symbol])
            quote = Web3.to_checksum_address(self.token_addresses[quote_symbol])

            # Always sort for Uniswap pool ordering
            token0, token1 = sorted([base, quote])

            fee = 3000
            tick_spacing = 60
            hooks = Web3.to_checksum_address('0x0000000000000000000000000000000000000000')

            # Get pool ID
            pool_id = Web3.keccak(abi_encode(
                ['address', 'address', 'uint24', 'int24', 'address'],
                [token0, token1, fee, tick_spacing, hooks]
            ))

            # Get spot price from Slot0
            sqrt_price_x96, _, _, _ = self.state_view.functions.getSlot0(pool_id).call()
            raw_price = (sqrt_price_x96 / (2**96)) ** 2

            decimals0 = await self.get_token_decimals(token0)
            decimals1 = await self.get_token_decimals(token1)

            # Calculate spot price with decimal adjustment
            price_token1_per_token0 = raw_price * (10 ** (decimals0 - decimals1))

            # Determine final spot price: base / quote
            spot_price = (price_token1_per_token0 
                        if base == token0 and quote == token1 
                        else 1 / price_token1_per_token0)
            
            quoterv4 = self.web3.eth.contract(
                address=Web3.to_checksum_address(self.contract_addresses["quoterv4"]),
                abi=self.abis["quoterv4"]
            )

            # Define amounts for quotes based on target_amount if provided
            if target_amount:
                # Generate a range of amounts around the target
                standard_amounts = [
                    target_amount,                      # Exact target
                ]
                # Add exact target amount if not already in the list
                if target_amount not in standard_amounts:
                    standard_amounts.insert(2, target_amount)
            else:
                # Default amounts if no target specified
                standard_amounts = [1.0]

            quotes = []
            target_quote = None

            for amount in standard_amounts:
                try:
                    zero_for_one = (base == token0)

                    # pick decimals for the input token (base) and output token (quote)
                    input_decimals = decimals0 if base == token0 else decimals1
                    output_decimals = decimals1 if base == token0 else decimals0
                    # Convert amount to wei based on decimals
                    amount_in_wei = Web3.to_wei(amount, 'ether') // (10 ** (18 - input_decimals))

                    # Construct the params tuple
                    quote_params = (
                        [token0, token1, fee, tick_spacing, hooks],  # poolKey
                        zero_for_one,                                # zeroForOne
                        amount_in_wei,                               # exactAmount
                        b""                                          # hookData (empty for no hooks)
                    )
                    quote_result = quoterv4.functions.quoteExactInputSingle(
                        quote_params
                    ).call()
                    
                    amount_out = quote_result[0] * (10 ** (18 - output_decimals)) / (10 ** 18)                    
                    
                    quote_data = {
                        "amount_in": amount,
                        "amount_out": amount_out,
                        "price": amount_out / amount if amount > 0 else 0,
                        "is_target": abs(amount - target_amount) < 0.0001 if target_amount else False
                    }
                    
                    quotes.append(quote_data)
                    
                    # Store target quote separately
                    if target_amount and abs(amount - target_amount) < 0.0001:
                        target_quote = quote_data

                except Exception as e:
                    logger.warning(f"Failed to get quote for amount {amount}: {e}")
                    continue

            price_info = {
                "summary": {
                    "pair": symbol,
                    "time": int(time.time()),
                    "status": "active" if sqrt_price_x96 > 0 else "uninitialized",
                    "target_amount": target_amount
                },
                "price_data": {
                    "spot_price": f"{spot_price:.8f}",
                    "sqrt_price_x96": sqrt_price_x96,
                    "raw_price": raw_price
                },
                "pool_info": {
                    "id": pool_id.hex(),
                    "token0": {
                        "address": token0,
                        "decimals": decimals0
                    },
                    "token1": {
                        "address": token1,
                        "decimals": decimals1
                    },
                    "fee_tier": "0.3%"
                },
                "quotes": quotes,
                "target_quote": target_quote,
                "metadata": {
                    "base_token": base,
                    "quote_token": quote,
                    "timestamp": int(time.time())
                }
            }
            
            limit_price = 0.0 
            UniswapV4Adapter.log_price_info(price_info, limit_price)

            return price_info

        except Exception as e:
            logger.error(f"Failed to fetch price and quotes for {symbol}: {e}")
            return None
        
    def log_price_info(price_info: dict, limit_price: float) -> None:
        lines = []
        lines.append("=" * 80)
        lines.append(f"PRICE UPDATE: {price_info['summary']['pair']}")
        lines.append("-" * 80)
        lines.append("Pool Status:")
        lines.append(f"  • Pool id    : {price_info['pool_info']['id']}")
        lines.append(f"  • Status     : {price_info['summary']['status']}")
        lines.append(f"  • Spot Price : {price_info['price_data']['spot_price']}")
        lines.append("-" * 40)
        
        target_amount = price_info['summary'].get('target_amount')
        if target_amount:
            lines.append(f"Target Amount: {target_amount}")
        
        if price_info.get('quotes'):
            lines.append("Quote Matrix:")
            lines.append(f"{'Amount In':>12} | {'Amount Out':>12} | {'Price':>12} | {'Target?':>7}")
            lines.append("-" * 50)
            for q in price_info['quotes']:
                is_target = q.get('is_target', False)
                target_marker = "→ TARGET" if is_target else ""
                lines.append(f"{q['amount_in']:12.4f} | {q['amount_out']:12.4f} | {q['price']:12.4f} | {target_marker}")
        else:
            lines.append("No valid quotes available")
            
        if price_info.get('target_quote'):
            tq = price_info['target_quote']
            lines.append("-" * 50)
            lines.append(f"TARGET QUOTE: {tq['amount_in']:.4f} → {tq['amount_out']:.4f} (Price: {tq['price']:.4f})")
        
        lines.append("-" * 80)
        lines.append(f"Limit Price : {limit_price}")
        ts = datetime.fromtimestamp(price_info['summary']['time']).strftime('%Y-%m-%d %H:%M:%S')
        lines.append(f"Last Updated: {ts}")
        lines.append("=" * 80)
        
        final_message = "\n".join(lines)
        logger.info(final_message)


    async def place_market_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Place a market algorithm order using the algorithm system.
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2"
            side: Order side ("buy" or "sell")
            quantity: Amount to trade
            client_algo_id: Unique identifier for the order
            instrument_type: Optional instrument type
            
        Returns:
            Dictionary with order status and details
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}
            
            # Import here to avoid circular dependencies
            from gq_oems_py.algorithms.MarketAlgorithm import place_market_algo
            
            # Set exchange name and account name for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4_test"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")
                
            # Register algorithm update callback if needed
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []
                
            # Register order update callback if needed
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []
                
            # Forward to the algorithm system
            result = await place_market_algo(
                adapter=self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                client_algo_id=client_algo_id,
                instrument_type=instrument_type
            )
            
            return result
                
        except Exception as e:
            error_msg = f"Failed to place market algo order: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }

    def _extract_transaction_info(self, receipt) -> Dict[str, Any]:
        """
        Extract essential transaction information from receipt for storage.
        
        Args:
            receipt: Transaction receipt (can be AttributeDict or dict)
            
        Returns:
            Dictionary with essential transaction info
        """
        try:
            if not receipt:
                return {}
                
            # Convert to dict if it's an AttributeDict
            if hasattr(receipt, '__dict__') and callable(getattr(receipt, 'items', None)):
                receipt_dict = dict(receipt)
            else:
                receipt_dict = receipt
                
            # Extract essential information
            transaction_info = {
                "transaction_hash": receipt_dict.get("transactionHash"),
                "block_number": receipt_dict.get("blockNumber"),
                "gas_used": receipt_dict.get("gasUsed"),
                "effective_gas_price": receipt_dict.get("effectiveGasPrice"),
                "status": receipt_dict.get("status"),
                "from": receipt_dict.get("from"),
                "to": receipt_dict.get("to"),
            }
            
            # Convert HexBytes to hex strings if present
            for key, value in transaction_info.items():
                if hasattr(value, "hex"):
                    transaction_info[key] = value.hex()
                    
            return transaction_info
            
        except Exception as e:
            logger.warning(f"Failed to extract transaction info from receipt: {e}")
            return {"error": "Failed to parse receipt"}
            
    async def _execute_market_order(
        self,
        symbol: str,
        side: str,
        quantity: float,
        client_algo_id: str,
    ) -> Dict[str, Any]:
        """
        Actual market order execution logic (previously in place_market_algo)
        """
        try:
            # Parse the symbol to get token addresses
            token_symbols = symbol.split('/')
            if len(token_symbols) != 2:
                return {
                    "status": "error", 
                    "message": f"Invalid symbol format: {symbol}. Expected format: TOKEN1/TOKEN2"
                }

            base_token, quote_token = token_symbols[0], token_symbols[1]

            # Get token addresses from the stored mapping
            if base_token not in self.token_addresses or quote_token not in self.token_addresses:
                return {
                    "status": "error",
                    "message": f"Unsupported tokens: {base_token} or {quote_token}"
                }

            base_token_address = self.token_addresses[base_token]
            quote_token_address = self.token_addresses[quote_token]

            # Set default parameters for the swap
            fee = 3000  # 0.3% fee tier
            tick_spacing = 60
            deadline = int(time.time()) + 1200  # 10 minutes

            if side.lower() == "buy":
                # Buying base token with quote token
                # Use exact output swap since we know how much base token we want to receive
                token_in = quote_token_address
                token_out = base_token_address
                amount_out = quantity  # The quantity of base token we want to receive
                amount_in_maximum = 100.0  # Set a reasonable maximum input amount
                quote_info = await self._fetch_current_price(symbol, target_amount=amount_out)
                quoted_price = None
                if quote_info and quote_info.get("target_quote"):
                    quoted_price = quote_info["target_quote"]["amount_out"]
                try:
                    result = await self.place_single_swap_out_algo(
                        token_in=token_in,
                        token_out=token_out,
                        amount_out=amount_out,
                        amount_in_maximum=amount_in_maximum,
                        fee=fee,
                        tick_spacing=tick_spacing,
                        deadline=deadline
                    )
                except Exception as e:
                    logger.error(f"Error occurred while placing swap out order: {e}")
                    # Store error in completed_orders so watch_order can see it
                    self.completed_orders[client_algo_id] = {
                        "status": "error",
                        "message": str(e)
                    }
                    return self.completed_orders[client_algo_id]

                # Create a storage for completed orders if it doesn't exist
                if not hasattr(self, "completed_orders"):
                    self.completed_orders = {}
                
                # If the swap was successful, store order completion data for watch_order
                if result.get("status") == "success":
                    # Extract essential transaction info from receipt
                    transaction_info = self._extract_transaction_info(result.get("receipt"))
                    # Extract price info if available
                    execution_price = None
                    if "receipt" in result and result["receipt"] is not None:
                        # You may need to calculate the execution price from the event logs
                        # result["receipt"] = dict(result["receipt"])
                        # For simplicity, we'll use 0 here, but ideally you'd extract the actual rate
                        execution_price = 0  # Replace with actual price calculation

                    # Calculate USD values for the exact traded amounts
                    base_value_usd = await self.calculate_token_value_in_usdc(base_token, quantity)
                    quote_value_usd = await self.calculate_token_value_in_usdc(quote_token, quoted_price) if quoted_price else None

                    filled_value_usdc = None
                    if base_value_usd is not None and quote_value_usd is not None and quoted_price and quoted_price > 0:
                        base_per_quote = 1.0 / quoted_price
                        filled_value_usdc = quote_value_usd
                            
                    # Store completion data for watch_order to find
                    self.completed_orders[client_algo_id] = {
                        "status": "filled",
                        "filled": quantity,
                        "remaining": 0.0,
                        "price": execution_price,
                        "quote_price": quoted_price,
                        "filled_value_usdc": filled_value_usdc,
                        "side": side.lower(),
                        "base_value_usd": base_value_usd,
                        "quote_value_usd": quote_value_usd,
                        "exchange_order_update": {
                            "transaction_hash": result.get("transaction_hash"),
                            "timestamp": datetime.now().isoformat(),
                            "receipt": str(result.get("receipt")) if result.get("receipt") else None,
                            "transaction_info": transaction_info
                        }
                    }
                    
                    logger.info(f"Stored completion data for order {client_algo_id}")
                
                    # # --- TSL EXIT LOGIC ---
                    # if client_algo_id.endswith("-exit"):
                    #     parent_algo_id = client_algo_id[:-5]  # Remove '-exit'
                    #     # Mark parent TSL order as filled
                    #     if hasattr(self, "limit_orders") and parent_algo_id in self.limit_orders:
                    #         self.limit_orders[parent_algo_id]["status"] = "filled"
                    #         self.limit_orders[parent_algo_id]["filled"] = quantity
                    #         self.limit_orders[parent_algo_id]["remaining"] = 0.0
                    #         self.limit_orders[parent_algo_id]["execution_price"] = 0  # You can extract actual price if needed

                    #     # Also update completed_orders for parent
                    #     if hasattr(self, "completed_orders"):
                    #         self.completed_orders[parent_algo_id] = {
                    #             "status": "filled",
                    #             "filled": quantity,
                    #             "remaining": 0.0,
                    #             "price": 0,
                    #             "exchange_order_update": {
                    #                 "transaction_hash": result.get("transaction_hash"),
                    #                 "timestamp": datetime.now().isoformat(),
                    #                 "receipt": result.get("receipt")
                    #             }
                    #         }

                    #     # Optionally, broadcast an algo update for the parent TSL
                    #     if hasattr(self, "algo_update_callbacks"):
                    #         algo_update = {
                    #             "algo_update": {
                    #                 "exchange_name": getattr(self, "exchange_name", "uniswapv4test"),
                    #                 "account_name": getattr(self, "account_name", "default"),
                    #                 "client_algo_id": parent_algo_id,
                    #                 "algorithm_id": parent_algo_id,
                    #                 "status": "filled",
                    #                 "filled_quantity": quantity,
                    #                 "price": 0,
                    #                 "transaction_hash": result.get("transaction_hash", ""),
                    #                 "timestamp": datetime.now().isoformat()
                    #             }
                    #         }
                    #         for callback in self.algo_update_callbacks:
                    #             if callable(callback):
                    #                 asyncio.create_task(callback(algo_update))
                return result
                
            elif side.lower() == "sell":
                # Selling base token for quote token
                # Use exact input swap since we know how much base token we want to sell
                token_in = base_token_address
                token_out = quote_token_address
                amount_in = quantity  # The quantity of base token we want to sell
                amount_out_minimum = 0  # Set minimum amount of quote tokens to receive
                quote_info = await self._fetch_current_price(symbol, target_amount=amount_in)
                quoted_price = None
                if quote_info and quote_info.get("target_quote"):
                    quoted_price = quote_info["target_quote"]["amount_out"]
                try:
                    result = await self.place_single_swap_in_algo(
                        token_in=token_in,
                        token_out=token_out,
                        amount_in=amount_in,
                        amount_out_minimum=amount_out_minimum,
                        fee=fee,
                        tick_spacing=tick_spacing,
                        deadline=deadline
                    )
                except Exception as e:
                    logger.error(f"Error occurred while placing swap in order: {e}")
                    # Store error in completed_orders so watch_order can see it
                    self.completed_orders[client_algo_id] = {
                        "status": "error",
                        "message": str(e)
                    }
                    return self.completed_orders[client_algo_id]

                # Create a storage for completed orders if it doesn't exist
                if not hasattr(self, "completed_orders"):
                    self.completed_orders = {}
                
                # If the swap was successful, store order completion data for watch_order
                if result.get("status") == "success":
                    # Extract essential transaction info from receipt
                    transaction_info = self._extract_transaction_info(result.get("receipt"))
                    
                    # Extract price info if available
                    execution_price = None
                    if "receipt" in result and result["receipt"] is not None:
                        # You may need to calculate the execution price from the event logs
                        # For simplicity, we'll use 0 here, but ideally you'd extract the actual rate
                        execution_price = 0  # Replace with actual price calculation
                    
                    # Calculate USD values for the exact traded amounts
                    base_value_usd = await self.calculate_token_value_in_usdc(base_token, quantity)
                    quote_value_usd = await self.calculate_token_value_in_usdc(quote_token, quoted_price) if quoted_price else None

                    filled_value_usdc = None
                    if base_value_usd is not None:
                        filled_value_usdc = base_value_usd

                    
                    # Store completion data for watch_order to find
                    self.completed_orders[client_algo_id] = {
                        "status": "filled",
                        "filled": quantity,
                        "remaining": 0.0,
                        "price": execution_price,
                        "quote_price": quoted_price,
                        "filled_value_usdc": filled_value_usdc,
                        "side": side.lower(),
                        "base_value_usd": base_value_usd,
                        "quote_value_usd": quote_value_usd,
                        "exchange_order_update": {
                            "transaction_hash": result.get("transaction_hash"),
                            "timestamp": datetime.now().isoformat(),
                            "transaction_info": transaction_info
                        }
                    }
                    
                    logger.info(f"Stored completion data for order {client_algo_id}")
                
                    # --- TSL EXIT LOGIC ---
                    if client_algo_id.endswith("-exit"):
                        parent_algo_id = client_algo_id[:-5]  # Remove '-exit'
                        # Mark parent TSL order as filled
                        if hasattr(self, "limit_orders") and parent_algo_id in self.limit_orders:
                            self.limit_orders[parent_algo_id]["status"] = "filled"
                            self.limit_orders[parent_algo_id]["filled"] = quantity
                            self.limit_orders[parent_algo_id]["remaining"] = 0.0
                            self.limit_orders[parent_algo_id]["execution_price"] = 0  # You can extract actual price if needed

                        # # Also update completed_orders for parent
                        # if hasattr(self, "completed_orders"):
                        #     self.completed_orders[parent_algo_id] = {
                        #         "status": "filled",
                        #         "filled": quantity,
                        #         "remaining": 0.0,
                        #         "price": 0,
                        #         "exchange_order_update": {
                        #             "transaction_hash": result.get("transaction_hash"),
                        #             "timestamp": datetime.now().isoformat(),
                        #             "receipt": result.get("receipt")
                        #         }
                        #     }

                        # # Optionally, broadcast an algo update for the parent TSL
                        # if hasattr(self, "algo_update_callbacks"):
                        #     algo_update = {
                        #         "algo_update": {
                        #             "exchange_name": getattr(self, "exchange_name", "uniswapv4test"),
                        #             "account_name": getattr(self, "account_name", "default"),
                        #             "client_algo_id": parent_algo_id,
                        #             "algorithm_id": parent_algo_id,
                        #             "status": "filled",
                        #             "filled_quantity": quantity,
                        #             "price": 0,
                        #             "transaction_hash": result.get("transaction_hash", ""),
                        #             "timestamp": datetime.now().isoformat()
                        #         }
                        #     }
                        #     for callback in self.algo_update_callbacks:
                        #         if callable(callback):
                        #             asyncio.create_task(callback(algo_update))
                
                return result
                
            else:
                return {
                    "status": "error",
                    "message": f"Invalid side: {side}. Expected 'buy' or 'sell'"
                }
                

        except Exception as e:
            error_msg = f"Failed to execute market order: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }
            
    # async def place_oco_algo(
    #     self,
    #     symbol: str,
    #     side: str,
    #     quantity: float,
    #     price: float,
    #     secondary_price: float,
    #     client_algo_id: str = None,
    #     instrument_type: Optional[str] = None,
    #     **kwargs
    # ) -> dict:
    #     """
    #     Standalone OCO (One-Cancels-Other) implementation for UniswapV4TestAdapter.
    #     Places two limit orders: primary and secondary. If one fills, the other is cancelled.
    #     """
    #     if not self.authenticated:
    #         return {"status": "error", "message": "Not authenticated"}

    #     logger.info("PLACING OCO ALGO")
    #     # Generate unique IDs for the two legs
    #     import uuid
    #     algo_id = str(uuid.uuid4())
    #     if not client_algo_id:
    #         client_algo_id = f"oco_{algo_id[:8]}"
    #     # Generate unique IDs for both legs using generate_algo_params
    #     primary_params = self.generate_algo_params(client_algo_id)
    #     secondary_params = self.generate_algo_params(client_algo_id)
    #     primary_id = primary_params["clientOrderId"]
    #     secondary_id = secondary_params["clientOrderId"]

    #     # Create initial order state in completed_orders
    #     if not hasattr(self, "completed_orders"):
    #         self.completed_orders = {}
    #     self.completed_orders[client_algo_id] = {
    #         "status": "received",
    #         "filled": 0.0,
    #         "remaining": quantity,
    #         "price": price,
    #         "symbol": symbol,
    #         "secondary_price": secondary_price,
    #         "timestamp": datetime.now().isoformat()
    #     }

    #     # Broadcast initial status
    #     if hasattr(self, "algo_update_callbacks"):
    #         algo_update = {
    #             "algo_update": {
    #                 "exchange_name": self.exchange_name,
    #                 "account_name": self.account_name,
    #                 "client_algo_id": client_algo_id,
    #                 "algorithm_id": str(algo_id),
    #                 "status": "received",
    #                 "parameters": {
    #                     "algorithm_type": "oco",
    #                     "symbol": symbol,
    #                     "side": side,
    #                     "quantity": quantity,
    #                     "price": price,
    #                     "secondary_price": secondary_price
    #                 },
    #                 "timestamp": datetime.now().isoformat()
    #             }
    #         }
    #         for cb in self.algo_update_callbacks:
    #             if callable(cb):
    #                 asyncio.create_task(cb(algo_update))

    #     logger.info("PLACING LIMIT ALGO FOR PARTIAL FILLS")

    #     # Place both limit orders (primary and secondary)
    #     primary_result = await self.place_limit_algo(
    #         symbol=symbol,
    #         side=side,
    #         quantity=quantity,
    #         price=price,
    #         client_algo_id=primary_id,
    #         allow_partial=False
    #     )
    #     if primary_result.get("status") != "success":
    #         return {
    #             "status": "error",
    #             "message": f"Primary leg failed: {primary_result.get('message')}",
    #             "client_algo_id": client_algo_id,
    #         }

    #     if not primary_result or primary_result.get("status") not in ["success", "queued"]:
    #         error_msg = f"Primary leg failed: {primary_result.get('message', 'Unknown error')}"
    #         # Broadcast error status
    #         if hasattr(self, "algo_update_callbacks"):
    #             error_update = {
    #                 "algo_update": {
    #                     "exchange_name": self.exchange_name,
    #                     "account_name": self.account_name,
    #                     "client_algo_id": client_algo_id,
    #                     "algorithm_id": str(algo_id),
    #                     "status": "error",
    #                     "parameters": {
    #                         "algorithm_type": "oco",
    #                         "symbol": symbol,
    #                         "side": side,
    #                         "quantity": quantity,
    #                         "price": price,
    #                         "secondary_price": secondary_price
    #                     },
    #                     "error": error_msg,
    #                     "timestamp": datetime.now().isoformat()
    #                 }
    #             }
    #             for cb in self.algo_update_callbacks:
    #                 if callable(cb):
    #                     asyncio.create_task(cb(error_update))
    #         return {
    #             "status": "error",
    #             "message": error_msg,
    #             "client_algo_id": client_algo_id
    #         }

    #     # Broadcast in_progress status after primary leg placement
    #     if hasattr(self, "algo_update_callbacks"):
    #         progress_update = {
    #             "algo_update": {
    #                 "exchange_name": self.exchange_name,
    #                 "account_name": self.account_name,
    #                 "client_algo_id": client_algo_id,
    #                 "algorithm_id": str(algo_id),
    #                 "status": "in_progress",
    #                 "parameters": {
    #                     "algorithm_type": "oco",
    #                     "symbol": symbol,
    #                     "side": side,
    #                     "quantity": quantity,
    #                     "price": price,
    #                     "secondary_price": secondary_price
    #                 },
    #                 "primary_order_id": primary_id,
    #                 "timestamp": datetime.now().isoformat()
    #             }
    #         }
    #         for cb in self.algo_update_callbacks:
    #             if callable(cb):
    #                 asyncio.create_task(cb(progress_update))
            
    #     # --- Wait for primary order to execute or partial fill before placing secondary ---
    #     # We'll poll the order status for a short period (e.g., 10 seconds, polling every 1s)
    #     max_wait = 60.0
    #     poll_interval = 2.0
    #     waited = 0.0
    #     while waited < max_wait:
    #         primary_order_info = await self.fetch_order(primary_id, symbol)
    #         primary_status = primary_order_info.get("status")
    #         primary_filled = primary_order_info.get("filled", 0.0)
    #         primary_remaining = primary_order_info.get("remaining", quantity)
    #         # If any fill or terminal state, do NOT place secondary
    #         if primary_status in ("filled", "closed", "partial", "partially_filled") or (primary_filled > 0):
    #             logger.info(f"OCO: Primary leg {primary_id} filled/partially filled ({primary_status}), skipping secondary leg.")
    #             return {
    #                 "status": "success",
    #                 "message": "OCO completed with primary leg fill before secondary placement",
    #                 "client_algo_id": client_algo_id,
    #                 "primary_id": primary_id,
    #                 "secondary_id": None,
    #                 "primary_status": primary_status,
    #                 "primary_filled": primary_filled,
    #                 "primary_remaining": primary_remaining,
    #             }
    #         if primary_status in ("canceled", "rejected", "expired", "failed"):
    #             logger.info(f"OCO: Primary leg {primary_id} failed ({primary_status}), aborting OCO.")
    #             return {
    #                 "status": "error",
    #                 "message": f"Primary leg failed: {primary_status}",
    #                 "client_algo_id": client_algo_id,
    #             }
    #         await asyncio.sleep(poll_interval)
    #         waited += poll_interval
            
    #     secondary_result = await self.place_limit_algo(
    #         symbol=symbol,
    #         side=side,
    #         quantity=quantity,
    #         price=secondary_price,
    #         client_algo_id=secondary_id,
    #         allow_partial=False
    #     )
    #     if not secondary_result or secondary_result.get("status") not in ["success", "queued"]:
    #         # Cancel primary order
    #         await self.cancel_order(primary_id)
    #         error_msg = f"Secondary leg failed: {secondary_result.get('message', 'Unknown error')}"
    #         # Broadcast error status
    #         if hasattr(self, "algo_update_callbacks"):
    #             error_update = {
    #                 "algo_update": {
    #                     "exchange_name": self.exchange_name,
    #                     "account_name": self.account_name,
    #                     "client_algo_id": client_algo_id,
    #                     "algorithm_id": str(algo_id),
    #                     "status": "error",
    #                     "parameters": {
    #                         "algorithm_type": "oco",
    #                         "symbol": symbol,
    #                         "side": side,
    #                         "quantity": quantity,
    #                         "price": price,
    #                         "secondary_price": secondary_price
    #                     },
    #                     "error": error_msg,
    #                     "timestamp": datetime.now().isoformat()
    #                 }
    #             }
    #             for cb in self.algo_update_callbacks:
    #                 if callable(cb):
    #                     asyncio.create_task(cb(error_update))
    #         return {
    #             "status": "error",
    #             "message": error_msg,
    #             "client_algo_id": client_algo_id
    #         }

    #     # Track OCO state
    #     if not hasattr(self, "oco_algorithms"):
    #         self.oco_algorithms = {}
    #     self.oco_algorithms[client_algo_id] = {
    #         "primary_id": primary_id,
    #         "secondary_id": secondary_id,
    #         "active": True,
    #     }

    #     # Start monitoring both orders
    #     async def monitor_oco_leg(order_id, other_id, leg_name):
    #         async for update in self.watch_order(order_id, symbol):
    #             status = update.get("status")
    #             if status in ("filled", "closed"):
    #                 # Cancel the other leg
    #                 await self.cancel_order(other_id)
    #                 # Mark OCO as completed
    #                 self.oco_algorithms[client_algo_id]["active"] = False
    #                 # Broadcast OCO completion
    #                 if hasattr(self, "algo_update_callbacks"):
    #                     algo_update = {
    #                         "algo_update": {
    #                             "exchange_name": getattr(self, "exchange_name", "uniswap_v4"),
    #                             "account_name": getattr(self, "account_name", "default"),
    #                             "client_algo_id": client_algo_id,
    #                             "algorithm_id": client_algo_id,
    #                             "status": "completed",
    #                             "parameters": {
    #                                 "algorithm_type": "oco",
    #                                 "symbol": symbol,
    #                                 "side": side,
    #                                 "quantity": quantity,
    #                                 "price": price,
    #                                 "secondary_price": secondary_price,
    #                             },
    #                             "filled_leg": leg_name,
    #                             "timestamp": datetime.now().isoformat(),
    #                         }
    #                     }
    #                     for cb in self.algo_update_callbacks:
    #                         if callable(cb):
    #                             asyncio.create_task(cb(algo_update))
    #                 break
    #             elif status in ("canceled", "cancelled", "rejected", "error"):
    #                 # If one leg is cancelled/rejected, just stop monitoring
    #                 break

    #     asyncio.create_task(monitor_oco_leg(primary_id, secondary_id, "primary"))
    #     asyncio.create_task(monitor_oco_leg(secondary_id, primary_id, "secondary"))

    #     return {
    #         "status": "success",
    #         "message": "Standalone OCO algorithm started",
    #         "client_algo_id": client_algo_id,
    #         "primary_id": primary_id,
    #         "secondary_id": secondary_id,
    #     }
    
    async def place_oco_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        price: float,
        secondary_price: float,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
        **kwargs
    ) -> dict:
        """
        Standalone OCO (One-Cancels-Other) implementation for UniswapV4TestAdapter.
        Places two limit orders: primary and secondary. If one fills, the other is cancelled.
        """
        if not self.authenticated:
            return {"status": "error", "message": "Not authenticated"}

        logger.info("PLACING OCO ALGO")
        import uuid
        algo_id = str(uuid.uuid4())
        if not client_algo_id:
            client_algo_id = f"oco_{algo_id[:8]}"
        primary_params = self.generate_algo_params(client_algo_id)
        secondary_params = self.generate_algo_params(client_algo_id)
        primary_id = primary_params["clientOrderId"]
        secondary_id = secondary_params["clientOrderId"]

        if not hasattr(self, "completed_orders"):
            self.completed_orders = {}
        self.completed_orders[client_algo_id] = {
            "status": "received",
            "filled": 0.0,
            "remaining": quantity,
            "price": price,
            "symbol": symbol,
            "secondary_price": secondary_price,
            "timestamp": datetime.now().isoformat()
        }

        # Broadcast initial status
        if hasattr(self, "algo_update_callbacks"):
            algo_update = {
                "algo_update": {
                    "exchange_name": self.exchange_name,
                    "account_name": self.account_name,
                    "client_algo_id": client_algo_id,
                    "algorithm_id": str(algo_id),
                    "status": "received",
                    "parameters": {
                        "algorithm_type": "oco",
                        "symbol": symbol,
                        "side": side,
                        "quantity": quantity,
                        "price": price,
                        "secondary_price": secondary_price
                    },
                    "timestamp": datetime.now().isoformat()
                }
            }
            for cb in self.algo_update_callbacks:
                if callable(cb):
                    asyncio.create_task(cb(algo_update))

        logger.info("PLACING LIMIT ALGO FOR PARTIAL FILLS")

        # Start the OCO logic as a background task
        async def oco_logic():
            # Place primary leg
            primary_result = await self.place_limit_algo(
                symbol=symbol,
                side=side,
                quantity=quantity,
                price=price,
                client_algo_id=primary_id,
                allow_partial=False
            )
            if not primary_result or primary_result.get("status") not in ["success", "queued"]:
                error_msg = f"Primary leg failed: {primary_result.get('message', 'Unknown error')}"
                if hasattr(self, "algo_update_callbacks"):
                    error_update = {
                        "algo_update": {
                            "exchange_name": self.exchange_name,
                            "account_name": self.account_name,
                            "client_algo_id": client_algo_id,
                            "algorithm_id": str(algo_id),
                            "status": "error",
                            "parameters": {
                                "algorithm_type": "oco",
                                "symbol": symbol,
                                "side": side,
                                "quantity": quantity,
                                "price": price,
                                "secondary_price": secondary_price
                            },
                            "error": error_msg,
                            "timestamp": datetime.now().isoformat()
                        }
                    }
                    for cb in self.algo_update_callbacks:
                        if callable(cb):
                            asyncio.create_task(cb(error_update))
                return

            # Broadcast in_progress status after primary leg placement
            if hasattr(self, "algo_update_callbacks"):
                progress_update = {
                    "algo_update": {
                        "exchange_name": self.exchange_name,
                        "account_name": self.account_name,
                        "client_algo_id": client_algo_id,
                        "algorithm_id": str(algo_id),
                        "status": "in_progress",
                        "parameters": {
                            "algorithm_type": "oco",
                            "symbol": symbol,
                            "side": side,
                            "quantity": quantity,
                            "price": price,
                            "secondary_price": secondary_price
                        },
                        "primary_order_id": primary_id,
                        "timestamp": datetime.now().isoformat()
                    }
                }
                for cb in self.algo_update_callbacks:
                    if callable(cb):
                        asyncio.create_task(cb(progress_update))

            # Poll for primary fill/terminal state
            max_wait = 60.0
            poll_interval = 2.0
            waited = 0.0
            while waited < max_wait:
                primary_order_info = await self.fetch_order(primary_id, symbol)
                primary_status = primary_order_info.get("status")
                primary_filled = primary_order_info.get("filled", 0.0)
                primary_remaining = primary_order_info.get("remaining", quantity)
                if primary_status in ("filled", "closed", "partial", "partially_filled") or (primary_filled > 0):
                    logger.info(f"OCO: Primary leg {primary_id} filled/partially filled ({primary_status}), skipping secondary leg.")
                    return
                if primary_status in ("canceled", "rejected", "expired", "failed"):
                    logger.info(f"OCO: Primary leg {primary_id} failed ({primary_status}), aborting OCO.")
                    return
                await asyncio.sleep(poll_interval)
                waited += poll_interval

            # Place secondary leg
            secondary_result = await self.place_limit_algo(
                symbol=symbol,
                side=side,
                quantity=quantity,
                price=secondary_price,
                client_algo_id=secondary_id,
                allow_partial=False
            )
            if not secondary_result or secondary_result.get("status") not in ["success", "queued"]:
                await self.cancel_order(primary_id)
                error_msg = f"Secondary leg failed: {secondary_result.get('message', 'Unknown error')}"
                if hasattr(self, "algo_update_callbacks"):
                    error_update = {
                        "algo_update": {
                            "exchange_name": self.exchange_name,
                            "account_name": self.account_name,
                            "client_algo_id": client_algo_id,
                            "algorithm_id": str(algo_id),
                            "status": "error",
                            "parameters": {
                                "algorithm_type": "oco",
                                "symbol": symbol,
                                "side": side,
                                "quantity": quantity,
                                "price": price,
                                "secondary_price": secondary_price
                            },
                            "error": error_msg,
                            "timestamp": datetime.now().isoformat()
                        }
                    }
                    for cb in self.algo_update_callbacks:
                        if callable(cb):
                            asyncio.create_task(cb(error_update))
                return

            # Track OCO state
            if not hasattr(self, "oco_algorithms"):
                self.oco_algorithms = {}
            self.oco_algorithms[client_algo_id] = {
                "primary_id": primary_id,
                "secondary_id": secondary_id,
                "active": True,
            }

            # Start monitoring both orders
            async def monitor_oco_leg(order_id, other_id, leg_name):
                async for update in self.watch_order(order_id, symbol):
                    status = update.get("status")
                    if status in ("filled", "closed"):
                        await self.cancel_order(other_id)
                        self.oco_algorithms[client_algo_id]["active"] = False
                        if hasattr(self, "algo_update_callbacks"):
                            algo_update = {
                                "algo_update": {
                                    "exchange_name": getattr(self, "exchange_name", "uniswap_v4"),
                                    "account_name": getattr(self, "account_name", "default"),
                                    "client_algo_id": client_algo_id,
                                    "algorithm_id": client_algo_id,
                                    "status": "completed",
                                    "parameters": {
                                        "algorithm_type": "oco",
                                        "symbol": symbol,
                                        "side": side,
                                        "quantity": quantity,
                                        "price": price,
                                        "secondary_price": secondary_price,
                                    },
                                    "filled_leg": leg_name,
                                    "timestamp": datetime.now().isoformat(),
                                }
                            }
                            for cb in self.algo_update_callbacks:
                                if callable(cb):
                                    asyncio.create_task(cb(algo_update))
                        break
                    elif status in ("canceled", "cancelled", "rejected", "error"):
                        break

            asyncio.create_task(monitor_oco_leg(primary_id, secondary_id, "primary"))
            asyncio.create_task(monitor_oco_leg(secondary_id, primary_id, "secondary"))

        # Start OCO logic in the background
        asyncio.create_task(oco_logic())

        # Return immediately so REST client gets a fast response
        return {
            "status": "success",
            "message": "OCO algorithm started",
            "client_algo_id": client_algo_id,
            "primary_id": primary_id,
            "secondary_id": secondary_id,
        }
            
    # Update the place_limit_algo method

    async def place_limit_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        price: float,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Place a limit algorithm order using the algorithm system.
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2"
            side: Order side ("buy" or "sell")
            quantity: Amount to trade
            price: Limit price for the order
            client_algo_id: Unique identifier for the order
            instrument_type: Optional instrument type
            
        Returns:
            Dictionary with order status and details
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}
            
            # Import here to avoid circular dependencies
            from gq_oems_py.algorithms.LimitAlgorithm import place_limit_algo
            
            # Set exchange name and account name for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")
                
            # Register algorithm update callback if needed
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []
                
            # Register order update callback if needed
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []
                
            # logger.info(f"Placing limit algo: {symbol} {side} {quantity} @ {price} (client_algo_id: {client_algo_id})")
            
            # # Store order in limit_orders dictionary to track its status
            # self.limit_orders[client_algo_id] = {
            #     'algo_type': 'limit',
            #     'symbol': symbol,
            #     'side': side,
            #     'quantity': quantity,
            #     'price': price,
            #     'status': 'new',
            #     'start_time': time.time(),
            #     'client_algo_id': client_algo_id,
            #     'instrument_type': instrument_type,
            # }
            
            # Forward to the algorithm system
            result = await place_limit_algo(
                adapter=self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                price=price,
                client_algo_id=client_algo_id,
                instrument_type=instrument_type
            )
            
            return result
            
        except Exception as e:
            error_msg = f"Failed to queue limit order: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }
            
################################################# PARTIAL FILL LOGIC ##########################################################
          
    # Overloaded function for place_limit_algo. This function will handle partial fills for algorithms like OCO, limit edge, etc.        
    async def place_limit_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        price: float,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
        allow_partial: bool = False,  # <-- New parameter for OCO/partial fill support
    ) -> Dict[str, Any]:
        """
        Place a limit algorithm order, optionally allowing partial fills (for OCO).
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}

            # If allow_partial is True, use the direct partial fill logic
            if allow_partial:
                return await self._execute_limit_order_with_partial(
                    symbol=symbol,
                    side=side,
                    quantity=quantity,
                    price=price,
                    client_algo_id=client_algo_id,
                )

            # Otherwise, use the standard algo system (as before)
            from gq_oems_py.algorithms.LimitAlgorithm import place_limit_algo

            # Set exchange/account names for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4"
            if not hasattr(self, "account_name"):
                self.account_name = "default_account"

            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []

            result = await place_limit_algo(
                adapter=self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                price=price,
                client_algo_id=client_algo_id,
                instrument_type=instrument_type,
            )
            return result

        except Exception as e:
            logger.error(f"Failed to place limit order: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    async def _execute_limit_order_with_partial(
        self,
        symbol: str,
        side: str,
        quantity: float,
        price: float,
        client_algo_id: str,
    ) -> Dict[str, Any]:
        """
        Directly execute a limit order, supporting partial fills for OCO.
        If partially filled, place a market order for the filled part and cancel the rest.
        """
        try:
            logger.info("FIND MAX EXECUTABLE QUANTITY FOR PARTIAL FILL")
            # Find max executable quantity using find_max_executable_quantity function
            max_executable_qty = await self.find_max_executable_quantity(
                symbol=symbol,
                side=side,
                quantity=quantity,
            )
            if max_executable_qty is None:
                return {
                    "status": "error",
                    "message": f"Failed to determine max executable quantity for {symbol} at price {price}"
                }
            if max_executable_qty <= 0:
                return {
                    "status": "error",
                    "message": f"No executable quantity available for {symbol} at price {price}"
                }
            filled_qty = max_executable_qty
            remaining_qty = quantity - filled_qty

            # Place market order for filled part
            if filled_qty > 0:
                # await self._execute_market_order(
                #     symbol=symbol,
                #     side=side,
                #     quantity=filled_qty,
                #     client_algo_id=client_algo_id
                # )
                
                # place market algo
                await self.place_market_algo(
                    symbol=symbol,
                    side=side,
                    quantity=filled_qty,
                    client_algo_id=client_algo_id,
                )

            # Cancel the rest (handled by OCO logic in oco.py)
            # Optionally, you can call self.cancel_order(client_algo_id) here if needed
            
            # get order info to broadcast it correctly
            # order_info = await self.fetch_order(client_algo_id, symbol)

            # # Broadcast update for partial fill
            # self.broadcast_order_update(
            #     algo_id=client_algo_id,
            #     client_algo_id=client_algo_id,
            #     symbol=symbol,
            #     order_id=client_algo_id,
            #     status="partially_filled",
            #     filled=filled_qty,
            #     remaining=remaining_qty,
            #     price=price,
            #     exchange_order_data=order_info
            # )

            return {
                "status": "partially_filled",
                "message": f"Order partially filled: {filled_qty} filled, {remaining_qty} cancelled",
                "filled": filled_qty,
                "remaining": remaining_qty,
                "client_algo_id": client_algo_id,
            }
        except Exception as e:
            logger.error(f"Partial fill execution failed: {str(e)}")
            return {"status": "error", "message": str(e)}
        
################################################# PARTIAL FILL LOGIC ##########################################################
            
    async def _execute_limit_order(
        self,
        symbol: str,
        side: str,
        quantity: float,
        price: float,
        client_algo_id: str,
    ) -> Dict[str, Any]:
        """
        Actual limit order execution logic (previously in place_limit_algo)
        """
        
        if client_algo_id in self.monitor_tasks:
            task = self.monitor_tasks.pop(client_algo_id)
            task.cancel()
        task = asyncio.create_task(self._monitor_price(client_algo_id))
        self.monitor_tasks[client_algo_id] = task
        try:            
            # Parse the symbol to get token addresses
            token_symbols = symbol.split('/')
            if len(token_symbols) != 2:
                return {
                    "status": "error",
                    "message": f"Invalid symbol format: {symbol}. Expected format: TOKEN1/TOKEN2"
                }

            base_token, quote_token = token_symbols[0], token_symbols[1]

            # Get token addresses from the stored mapping
            if base_token not in self.token_addresses or quote_token not in self.token_addresses:
                return {
                    "status": "error",
                    "message": f"Unsupported tokens: {base_token} or {quote_token}"
                }

            base_token_address = self.token_addresses[base_token]
            quote_token_address = self.token_addresses[quote_token]

            # Store the limit order in temporary storage
            self.limit_orders[client_algo_id] = {
                "symbol": symbol,
                "side": side,
                "quantity": quantity,
                "price": price,
                "base_token": base_token_address,
                "quote_token": quote_token_address,
                "algo_type": "limit",
                "status": "pending"
            }

            # Create a storage for completed orders if it doesn't exist
            if not hasattr(self, "completed_orders"):
                self.completed_orders = {}
            
            # Store initial order status for watch_order to find - marked as "open"
            self.completed_orders[client_algo_id] = {
                "status": "open",
                "filled": 0.0,
                "remaining": quantity,
                "price": price,
                "exchange_order_update": {
                    "timestamp": datetime.now().isoformat(),
                    "order_type": "limit",
                    "symbol": symbol
                }
            }

            # Start monitoring price movements
            # asyncio.create_task(self._monitor_price(client_algo_id))

            return {
                "status": "success",
                "message": "Limit order placed successfully",
                "client_algo_id": client_algo_id,
                "parameters": {
                    "symbol": symbol,
                    "side": side,
                    "quantity": quantity,
                    "price": price
                }
            }

        except Exception as e:
            error_msg = f"Failed to place limit order: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }
            
    async def close(self) -> None:
        """Clean up resources"""
        if self.queue_processor_task:
            self.queue_processor_task.cancel()
            try:
                await self.queue_processor_task
            except asyncio.CancelledError:
                pass
                
        await super().close()

    async def _monitor_price(self, client_algo_id: str):
        """
        Monitor price movements and trigger a swap when the price reaches the limit.
        For limit_edge orders the condition is based on:
        - Buy: quoted price <= (spot price * (1 + slippage_percentage/100))
        - Sell: quoted price >= (spot price * (1 - slippage_percentage/100))
        For regular limit orders, the stored limit price is used.
        """
        try:
            order = self.limit_orders.get(client_algo_id)
            if not order:
                logger.error(f"Order with client_algo_id {client_algo_id} not found")
                return

            symbol = order["symbol"]
            side = order["side"]
            quantity = order["quantity"]
            algo_type = order.get("algo_type", "limit")
            logger.info(f"Monitoring price for order {client_algo_id} on {symbol}")

            while True:
                # Check if the order has been canceled
                if client_algo_id not in self.limit_orders:
                    logger.info(f"Order {client_algo_id} cancelled, stopping monitoring")
                    
                    # Update completed_orders to reflect cancellation
                    if hasattr(self, "completed_orders"):
                        self.completed_orders[client_algo_id] = {
                            "status": "canceled",
                            "filled": 0.0,
                            "remaining": quantity,
                            "price": order.get("price"),
                            "exchange_order_update": {
                                "timestamp": datetime.now().isoformat(),
                                "reason": "user_cancelled"
                            }
                        }
                    break
                
                price_info = await self._fetch_current_price(symbol, target_amount=quantity)
                if price_info is None:
                    logger.warning(f"Failed to fetch price for {symbol}")
                    await asyncio.sleep(5)
                    continue

                try:
                    spot_price = float(price_info["price_data"]["spot_price"])
                except (KeyError, ValueError) as e:
                    logger.error(f"Invalid price_data format: {price_info} – {e}")
                    await asyncio.sleep(5)
                    continue
                
                # Find quoted price for our exact quantity
                quoted_price = None
                for quote in price_info["quotes"]:
                    if abs(quote["amount_in"] - quantity) < 0.0001:
                        quoted_price = quote["price"]
                        break
                        
                if quoted_price is None:
                    logger.warning(f"No quote available for quantity {quantity}")
                    await asyncio.sleep(5)
                    continue

                logger.info(f"Current spot price: {spot_price:.8f}")

                if algo_type == "limit_edge":
                    # For limit_edge, use the stored slippage percentage.
                    slippage = order.get("slippage", 0.5)

                    if side.lower() == "buy":
                        acceptable_price = spot_price * (1 + slippage / 100)
                        logger.info(f"Limit Edge Buy: Acceptable <= {acceptable_price:.8f}, Quoted: {quoted_price:.8f}")
                        order_triggered = quoted_price <= acceptable_price
                    else:
                        acceptable_price = spot_price * (1 - slippage / 100)
                        logger.info(f"Limit Edge Sell: Acceptable >= {acceptable_price:.8f}, Quoted: {quoted_price:.8f}")
                        order_triggered = quoted_price >= acceptable_price
                else:
                    # For regular limit orders, compare quote price to the limit price
                    limit_price = order.get("price")
                    logger.info(f"Limit price: {limit_price}, Quote price: {quoted_price:.8f}")
                    order_triggered = (side.lower() == "buy" and quoted_price <= limit_price) or \
                                    (side.lower() == "sell" and quoted_price >= limit_price)

                if order_triggered:
                    logger.info(f"Price condition met for order {client_algo_id}. Triggering market order swap.")
                    result = await self.place_market_algo(
                        symbol=symbol,
                        side=side,
                        quantity=quantity,
                        # client_algo_id=f"{client_algo_id}-exec"
                        client_algo_id=client_algo_id,
                    )
                    
                    # Update order status in both dictionaries
                    order["status"] = result.get("status", "error")
                    order["receipt"] = result.get("receipt")
                    
                    # Update the completed_orders entry with filled status
                    if hasattr(self, "completed_orders"):
                        self.completed_orders[client_algo_id] = {
                            "status": "filled",
                            "filled": quantity,
                            "remaining": 0.0,
                            "price": quoted_price,
                            "exchange_order_update": {
                                "transaction_hash": result.get("transaction_hash", ""),
                                "timestamp": datetime.now().isoformat(),
                                "receipt": result.get("receipt"),
                                "execution_price": quoted_price
                            }
                        }
                    
                    logger.info(f"Order {client_algo_id} completed with status {result['status']}")
                    break

                await asyncio.sleep(5)

        except Exception as e:
            logger.error(f"Error monitoring price for order {client_algo_id}: {str(e)}")
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id]["status"] = "error"
            
            # Update completed_orders with error status
            if hasattr(self, "completed_orders"):
                self.completed_orders[client_algo_id] = {
                    "status": "error",
                    "filled": 0.0,
                    "remaining": order.get("quantity", 0),
                    "price": order.get("price"),
                    "error": str(e),
                    "exchange_order_update": {
                        "timestamp": datetime.now().isoformat(),
                        "error_details": str(e)
                    }
                }
                
    async def cancel_order(self, client_algo_id: str, stop_algo:Optional[bool] = True) -> dict:
        """
        Cancel a pending order by client_algo_id.
        For algorithm orders, this will also stop the running algorithm and broadcast status.
        """
        try:
            # Remove from limit_orders and completed_orders
            order = self.limit_orders.pop(client_algo_id, None)
            if not order:
                return {
                    "status": "error",
                    "message": f"No such order: {client_algo_id}"
                }

            # Remove from algorithms dict if present
            if stop_algo and hasattr(self, "algorithms"):
                for algo_id, algo in list(self.algorithms.items()):
                    if getattr(algo, "client_algo_id", None) == client_algo_id:
                        # Stop the algorithm task if running
                        if hasattr(algo, "active"):
                            algo.active = False
                        if hasattr(algo, "task") and algo.task and not algo.task.done():
                            algo.task.cancel()
                        # Broadcast cancelled status
                        if hasattr(algo, "_broadcast_algo_status"):
                            try:
                                algo._broadcast_algo_status("cancelled")
                            except Exception as e:
                                logger.error(f"Error broadcasting cancel status: {str(e)}")
                        del self.algorithms[algo_id]
                        break

            # Update completed_orders
            if not hasattr(self, "completed_orders"):
                self.completed_orders = {}
            self.completed_orders[client_algo_id] = {
                "status": "canceled",
                "filled": 0,
                "remaining": order.get("quantity", 0),
                "price": order.get("price"),
                "exchange_order_update": {
                    "timestamp": datetime.now().isoformat(),
                    "message": "Order cancelled by user"
                }
            }

            # Broadcast to callbacks
            if hasattr(self, "algo_update_callbacks"):
                algo_update = {
                    "algo_update": {
                        "exchange_name": getattr(self, "exchange_name", "uniswap_v4"),
                        "account_name": getattr(self, "account_name", "default"),
                        "client_algo_id": client_algo_id,
                        "algorithm_id": client_algo_id,
                        "status": "cancelled",
                        "parameters": order,
                        "timestamp": datetime.now().isoformat()
                    }
                }
                for cb in self.algo_update_callbacks:
                    if callable(cb):
                        asyncio.create_task(cb(algo_update))

            return {
                "status": "success",
                "message": f"Order {client_algo_id} successfully cancelled"
            }
        except Exception as e:
            logger.error(f"Failed to cancel order {client_algo_id}: {str(e)}")
            return {
                "status": "error",
                "message": str(e)
            }

    async def cancel_all_orders(self) -> dict:
        """
        Cancel all pending limit orders.
        """
        try:
            cancelled = []
            for client_algo_id, order in list(self.limit_orders.items()):
                quantity = order.get("quantity", 0)
                price = order.get("price")
                # remove from live orders
                del self.limit_orders[client_algo_id]
                cancelled.append(client_algo_id)

                # record final status so fetch_order yields a terminal state
                if not hasattr(self, "completed_orders"):
                    self.completed_orders = {}
                self.completed_orders[client_algo_id] = {
                    "status": "canceled",
                    "filled": 0.0,
                    "remaining": quantity,
                    "price": price,
                    "exchange_order_update": {
                        "timestamp": datetime.now().isoformat(),
                        "message": "Order canceled by cancel_all_orders"
                    }
                }

                # broadcast to any algo‐update callbacks
                if hasattr(self, "algo_update_callbacks"):
                    algo_update = {
                        "algo_update": {
                            "exchange_name": self.exchange_name,
                            "account_name": self.account_name,
                            "client_algo_id": client_algo_id,
                            "algorithm_id": client_algo_id,
                            "status": "cancelled",
                            "parameters": order,
                            "timestamp": datetime.now().isoformat()
                        }
                    }
                    for cb in self.algo_update_callbacks:
                        if callable(cb):
                            asyncio.create_task(cb(algo_update))

            return {
                "status": "success",
                "message": f"Cancelled {len(cancelled)} orders",
                "cancelled": cancelled
            }
        except Exception as e:
            logger.error(f"Failed to cancel all orders: {e}")
            return {"status": "error", "message": str(e), "cancelled": []}
            
    async def modify_order(
        self,
        client_algo_id: str,
        new_price: Optional[float] = None,
        new_quantity: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Modify an order by canceling and placing a new one.
        For all algo types, this cancels the current order and places a new one with updated params.
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}

            # 1. Check if the order exists
            original_order = self.limit_orders.get(client_algo_id)
            if not original_order:
                return {
                    "status": "error",
                    "message": f"No order found with client_algo_id: {client_algo_id}"
                }

            # 2. Save all relevant order details before cancellation
            symbol = original_order.get("symbol")
            side = original_order.get("side")
            algo_type = original_order.get("algo_type", "limit")
            duration = original_order.get("duration")
            instrument_type = original_order.get("instrument_type")
            price = original_order.get("price")
            slippage = original_order.get("slippage")
            trail_percent = original_order.get("trail_percent")
            expiry_time = original_order.get("expiry_time")
            secondary_price = original_order.get("secondary_price")

            # Determine what parameters to use (original or new)
            quantity = new_quantity if new_quantity is not None else original_order.get("quantity")
            use_price = new_price if new_price is not None else price

            # 3. Cancel the current order
            cancel_result = await self.cancel_order(client_algo_id)
            if cancel_result.get("status") != "success":
                return {
                    "status": "error",
                    "message": f"Failed to cancel order: {cancel_result.get('message')}"
                }

            # 4. Place a new order with the same client_algo_id but updated parameters
            if algo_type == "limit":
                return await self.place_limit_algo(
                    symbol=symbol,
                    side=side,
                    quantity=quantity,
                    price=use_price,
                    client_algo_id=client_algo_id,
                    instrument_type=instrument_type
                )
            elif algo_type == "limit_edge":
                return await self.place_limit_edge_algo(
                    symbol=symbol,
                    side=side,
                    quantity=quantity,
                    duration=duration,
                    client_algo_id=client_algo_id,
                    instrument_type=instrument_type
                )
            elif algo_type == "market_edge":
                return await self.place_market_edge_algo(
                    symbol=symbol,
                    side=side,
                    quantity=quantity,
                    duration=duration,
                    client_algo_id=client_algo_id,
                    instrument_type=instrument_type
                )
            elif algo_type == "trailing_stop_loss":
                return await self.place_trailing_stop_loss_algo(
                    symbol=symbol,
                    side=side,
                    quantity=quantity,
                    trail_percent=trail_percent,
                    client_algo_id=client_algo_id,
                    instrument_type=instrument_type
                )
            elif algo_type == "good_till_time":
                return await self.place_good_till_time_algo(
                    symbol=symbol,
                    side=side,
                    quantity=quantity,
                    price=use_price,
                    expiry_time=expiry_time,
                    client_algo_id=client_algo_id,
                    instrument_type=instrument_type
                )
            elif algo_type == "day":
                return await self.place_day_algo(
                    symbol=symbol,
                    side=side,
                    quantity=quantity,
                    price=use_price,
                    client_algo_id=client_algo_id,
                    instrument_type=instrument_type
                )
            elif algo_type == "oco":
                return await self.place_oco_algo(
                    symbol=symbol,
                    side=side,
                    quantity=quantity,
                    price=use_price,
                    secondary_price=secondary_price,
                    client_algo_id=client_algo_id,
                    instrument_type=instrument_type
                )
            else:
                return {
                    "status": "error",
                    "message": f"Unsupported algorithm type: {algo_type}"
                }

        except Exception as e:
            logger.error(f"Failed to modify order {client_algo_id}: {str(e)}")
            return {
                "status": "error",
                "message": str(e)
            }
            
    async def fetch_ticker(self, symbol: str) -> dict:
        """
        Fetch the latest price for the given symbol in standard ticker format.
        """
        try:
            price_info = await self._fetch_current_price(symbol)
            if price_info is None:
                return {
                    "symbol": symbol,
                    "last": None,
                    "status": "error",
                    "message": f"Failed to fetch price for {symbol}"
                }
            
            # Extract the spot price from the price info
            try:
                spot_price = float(price_info["price_data"]["spot_price"])
                return {
                    "symbol": symbol,
                    "last": spot_price,  # Add the last field with spot price
                    "price": price_info,
                    "status": "success"
                }
            except (KeyError, ValueError) as e:
                logger.error(f"Invalid price_data format: {e}")
                return {
                    "symbol": symbol,
                    "last": None,
                    "status": "error",
                    "message": f"Invalid price data format: {e}"
                }
        except Exception as e:
            logger.error(f"Error in fetch_ticker for {symbol}: {e}")
            return {
                "symbol": symbol,
                "last": None,
                "status": "error",
                "message": str(e)
            }
            
    async def place_market_edge_algo(
        self, 
        symbol: str,
        side: str,
        quantity: float,
        duration: int,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Place a market edge algorithm order using the algorithm system.
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2"
            side: Order side ("buy" or "sell")
            quantity: Amount to trade
            duration: Duration to monitor for optimal execution in seconds
            client_algo_id: Unique identifier for the order
            instrument_type: Optional instrument type
            
        Returns:
            Dictionary with order status and details
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}
            
            # Import here to avoid circular dependencies
            from gq_oems_py.algorithms.MarketEdgeAlgorithm import place_market_edge_algo
            
            # Generate a client_algo_id if not provided
            if not client_algo_id:
                client_algo_id = f"market_edge_{int(time.time())}_{symbol.replace('/', '')}"
            
            logger.info(f"Placing market edge algo: {symbol} {side} {quantity} with duration {duration}s (client_algo_id: {client_algo_id})")
                
            # Set exchange name and account name for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")
                
            # Register algorithm update callback if needed
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []
                
            # Register order update callback if needed
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []
                
            # Store order in limit_orders dictionary to track its status
            # This is just to keep track of the order in our local state
            self.limit_orders[client_algo_id] = {
                'algo_type': 'market_edge',
                'symbol': symbol,
                'side': side,
                'quantity': quantity,
                'duration': duration,
                'status': 'new',
                'start_time': time.time(),
                'client_algo_id': client_algo_id,
                'instrument_type': instrument_type,
            }
                
            # Forward to the algorithm system - this is the key step
            result = await place_market_edge_algo(
                exchange=self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                duration=duration,
                client_algo_id=client_algo_id,
                instrument_type=instrument_type
            )
            
            # Update order status based on result
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id]['status'] = result.get('status', 'error')
                self.limit_orders[client_algo_id]['algorithm_id'] = result.get('algorithm_id')
                
            return result
            
        except Exception as e:
            error_msg = f"Failed to place market edge algorithm order: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return {
                "status": "error",
                "message": error_msg
            }
            
    async def find_max_executable_quantity(self, symbol: str, side: str, quantity: float, slippage_pct: float = 2) -> float:
        """
        Find maximum executable quantity within the given slippage tolerance using binary search.
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2"
            side: Order side ("buy" or "sell")
            quantity: Requested amount to trade
            slippage_pct: Maximum slippage percentage allowed
            
        Returns:
            The maximum executable quantity within slippage tolerance
        """
        try:
            # Get current price info for reference
            price_info = await self._fetch_current_price(symbol)
            if not price_info:
                logger.error(f"Failed to fetch price for {symbol}")
                return 0.0
                
            spot_price = float(price_info["price_data"]["spot_price"])
            
            # Helper function to check if a quantity can be executed within slippage limit
            async def check_slippage(test_amount: float) -> tuple[bool, float]:
                try:
                    quote_info = await self._fetch_current_price(symbol, target_amount=test_amount)
                    if not quote_info or not quote_info.get("target_quote"):
                        return False, 0.0
                        
                    quoted_price = quote_info["target_quote"]["price"]  # This is the effective price per unit
                    
                    # Calculate slippage based on side
                    if side.lower() == "buy":
                        # For buy: slippage = (quoted_price - spot_price) / spot_price * 100
                        # Positive slippage means we're paying more than spot
                        slippage_actual = ((spot_price-quoted_price) / spot_price) * 100
                        acceptable = slippage_actual <= slippage_pct
                    else:  # sell
                        # For sell: slippage = (spot_price - quoted_price) / spot_price * 100  
                        # Positive slippage means we're receiving less than spot
                        slippage_actual = ((spot_price - quoted_price) / spot_price) * 100
                        acceptable = slippage_actual <= slippage_pct
                        
                    logger.debug(f"Amount: {test_amount}, Spot: {spot_price:.6f}, Quoted: {quoted_price:.6f}, Slippage: {slippage_actual:.2f}%, Acceptable: {acceptable}")
                    return acceptable, quoted_price
                    
                except Exception as e:
                    logger.error(f"Failed to get quote for amount {test_amount}: {e}")
                    return False, 0.0
            
            # Binary search for maximum executable quantity
            low, high = 0.0, quantity
            executable_quantity = 0.0
            precision = 0.01 * quantity  # Stopping threshold as percentage of total quantity
            
            while high - low > precision:
                mid = (low + high) / 2
                can_execute, quoted_price = await check_slippage(mid)
                
                if can_execute:
                    executable_quantity = mid
                    low = mid
                else:
                    high = mid
                    
            logger.info(f"Maximum executable quantity for {symbol} {side}: {executable_quantity:.6f}/{quantity:.6f} ({executable_quantity/quantity*100:.1f}%)")
            return executable_quantity
                
        except Exception as e:
            logger.error(f"Error in find_max_executable_quantity: {str(e)}")
            return 0.0
            
    async def get_price_history(self, symbol: str, timeframe: str = '1m', limit: int = 1) -> list:
        """
        Get price history for a symbol. For Uniswap adapter, we simulate this by using current price
        with 1.5% slippage to create high/low bands.
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2" (e.g., "WETH/USDC")
            timeframe: Time frame for the candles (ignored for Uniswap)
            limit: Number of candles to return (ignored for Uniswap)
            
        Returns:
            List of price history candles with format [timestamp, open, high, low, close, volume]
        """
        try:
            # Get current price for the symbol
            price_info = await self._fetch_current_price(symbol)
            if not price_info:
                logger.error(f"Failed to fetch price data for {symbol}")
                return []
                
            # Extract the spot price
            try:
                spot_price = float(price_info["price_data"]["spot_price"])
            except (KeyError, ValueError):
                logger.error(f"Invalid price data format from _fetch_current_price")
                return []
                
            # Calculate high and low with fixed 5% slippage
            slippage_pct = 5
            high_price = spot_price * (1 + slippage_pct/100)
            low_price = spot_price * (1 - slippage_pct/100)
            
            # Create a single candle with the current timestamp
            timestamp = int(time.time() * 1000)  # Use milliseconds for timestamp
            
            # Format: [timestamp, open, high, low, close, volume]
            candle = [timestamp, spot_price, high_price, low_price, spot_price, 0]
            
            logger.info(f"Generated price history for {symbol}: Spot={spot_price:.6f}, High={high_price:.6f}, Low={low_price:.6f}")
            
            return [candle]
            
        except Exception as e:
            logger.error(f"Error in get_price_history for {symbol}: {str(e)}")
            return []
        
    async def fetch_order(self, order_id: str, symbol: str = None) -> Dict[str, Any]:
        """
        Fetch details of an order by ID. Works for both straight orders and algos.
        """
        try:
            logger.info(f"Fetching order details for {order_id}")
            # strip execution suffix
            # is_exec = order_id.endswith("-exec")
            # base_id = order_id.replace("-exec", "") if is_exec else order_id

            # 1) completed_orders override
            if hasattr(self, "completed_orders") and order_id in self.completed_orders:
                cd = self.completed_orders[order_id]
                
                # Extract transaction info from exchange_order_update if available
                transaction_info = {}
                exchange_order_update = cd.get("exchange_order_update", {})
                if exchange_order_update:
                    transaction_info = exchange_order_update.get("transaction_info", {})
                    # For backward compatibility, also try transaction_hash directly
                    if not transaction_info and exchange_order_update.get("transaction_hash"):
                        transaction_info["transaction_hash"] = exchange_order_update.get("transaction_hash")
                    
                return {
                    "id": order_id,
                    "status": cd.get("status", "filled"),
                    "filled": cd.get("filled", 0),
                    "remaining": cd.get("remaining", 0),
                    "price": cd.get("price"),
                    "quote_price": cd.get("quote_price"),
                    "side": cd.get("side"),
                    "symbol": symbol or cd.get("symbol"),
                    "timestamp": cd.get("timestamp", int(time.time()*1000)),
                    "filled_value_usdc": cd.get("filled_value_usdc"),
                    "base_value_usd": cd.get("base_value_usd"),
                    "quote_value_usd": cd.get("quote_value_usd"),
                    # Include all transaction information
                    "transaction_hash": transaction_info.get("transaction_hash"),
                    "block_number": transaction_info.get("block_number"),
                    "gas_used": transaction_info.get("gas_used"),
                    "effective_gas_price": transaction_info.get("effective_gas_price"),
                    "transaction_status": transaction_info.get("status"),
                    "from_address": transaction_info.get("from"),
                    "to_address": transaction_info.get("to"),
                }

            # 2) match exec under base
            # if hasattr(self, "completed_orders"):
            #     for cid, cd in self.completed_orders.items():
            #         if cid.startswith(f"{base_id}-"):
            #             return {
            #                 "id": order_id,
            #                 "status": cd.get("status", "filled"),
            #                 "filled": cd.get("filled", 0),
            #                 "remaining": cd.get("remaining", 0),
            #                 "price": cd.get("price"),
            #                 "symbol": symbol or cd.get("symbol"),
            #                 "timestamp": cd.get("timestamp", int(time.time()*1000))
            #             }

            # 3) live limit_orders
            if order_id in self.limit_orders:
                od = self.limit_orders[order_id]
                algo_type = od.get("algo_type", "limit")
                status    = od.get("status", "pending")
                qty       = od.get("quantity", 0)
                price     = od.get("price", None)

                if algo_type == "market_edge":
                    # if it's reached a terminal status, return it
                    if status in ("filled","completed","error","canceled","cancelled"):
                        final = self.completed_orders.get(order_id, od)
                        
                        # Extract transaction info if available
                        transaction_info = {}
                        if isinstance(final, dict):
                            exchange_order_update = final.get("exchange_order_update", {})
                            if exchange_order_update:
                                transaction_info = exchange_order_update.get("transaction_info", {})
                                
                        return {
                            "id": order_id,
                            "status": final.get("status", status),
                            "filled": final.get("filled", qty),
                            "remaining": final.get("remaining", 0),
                            "price": final.get("price", price),
                            "quote_price": cd.get("quote_price"),
                            "symbol": symbol or final.get("symbol"),
                            "timestamp": final.get("timestamp", int(time.time()*1000)),
                            # Include transaction information
                            "transaction_hash": transaction_info.get("transaction_hash"),
                            "block_number": transaction_info.get("block_number"),
                            "gas_used": transaction_info.get("gas_used"),
                            "effective_gas_price": transaction_info.get("effective_gas_price"),
                            "transaction_status": transaction_info.get("status"),
                            "from_address": transaction_info.get("from"),
                            "to_address": transaction_info.get("to"),
                        }
                    # otherwise still running => force "open"
                    return {
                        "id": order_id,
                        "symbol": od.get("symbol", symbol),
                        "status": status,  # Use actual status from limit_orders
                        "filled": od.get("filled", 0.0),
                        "remaining": qty if status not in ("filled","completed") else 0.0,
                        "price": price or 0.0,
                        "timestamp": int(time.time()*1000),
                        "side": od.get("side", ""),
                        "type": "limit",
                        "algo_type": "market_edge"
                    }

                # non-market_edge algos / plain limit
                return {
                    "id": order_id,
                    "status": status,
                    "filled": qty if status == "filled" else 0.0,
                    "remaining": 0.0 if status == "filled" else qty,
                    "price": price,
                    "symbol": od.get("symbol", symbol),
                    "timestamp": int(time.time()*1000)
                }

            # 4) not found
            logger.warning(f"Order {order_id} not found")
            return {
                "id": order_id,
                "status": "error",
                "error": f"Order {order_id} not found",
                "symbol": symbol,
                "timestamp": int(time.time()*1000)
            }

        except Exception as e:
            logger.error(f"Error fetching order {order_id}: {e}")
            return {
                "id": order_id,
                "status": "error",
                "error": str(e),
                "symbol": symbol,
                "timestamp": int(time.time()*1000)
            }
            
    async def _handle_algorithm_update(self, update: Dict[str, Any]) -> None:
        """
        Handle algorithm status updates from the algorithm system
        
        Args:
            update: Algorithm status update
        """
        try:
            # Extract the inner update data
            algo_update = update.get("algo_update", {})
            client_algo_id = algo_update.get("client_algo_id")
            status = algo_update.get("status")
            
            if not client_algo_id:
                logger.warning(f"Received algorithm update without client_algo_id: {update}")
                return
                
            logger.info(f"Received algorithm update: {client_algo_id} - {status}")
            
            # Update our local tracking
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id].update({
                    "status": status,
                    "last_update": datetime.now().isoformat(),
                    # Copy any additional fields provided in the update
                    **{k: v for k, v in algo_update.items() if k not in ["status", "last_update"]}
                })
                
                # If cancelled, completed or error, move to completed orders
                if status in ["completed", "error", "filled", "cancelled", "canceled"]:
                    if not hasattr(self, "completed_orders"):
                        self.completed_orders = {}
                        
                    # Remove from active orders and add to completed orders
                    order_data = self.limit_orders.pop(client_algo_id, {})
                    self.completed_orders[client_algo_id] = {
                        **order_data,
                        "timestamp": int(time.time() * 1000),
                        "error": algo_update.get("error"),
                        "message": algo_update.get("message", f"Algorithm {status}")
                    }
                    
                    # If this was a cancellation, also remove from algorithms dictionary
                    if status in ["cancelled", "canceled"] and hasattr(self, "algorithms"):
                        for algo_id, algo in list(self.algorithms.items()):
                            if hasattr(algo, "client_algo_id") and algo.client_algo_id == client_algo_id:
                                logger.info(f"Removing cancelled algorithm {algo_id} from algorithms dictionary")
                                del self.algorithms[algo_id]
                                break
            
            # Broadcast to all registered callbacks
            if hasattr(self, "algo_update_callbacks"):
                for callback in self.algo_update_callbacks:
                    if callable(callback):
                        try:
                            # Just pass through the original update
                            asyncio.create_task(callback(update))
                        except Exception as e:
                            logger.error(f"Error in algo update callback: {str(e)}")
                            
        except Exception as e:
            logger.error(f"Error handling algorithm update: {str(e)}")
    
    async def place_limit_edge_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        duration: int = 30,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
        price: Optional[float] = None,
        threshold: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Place a limit edge algorithm order using the algorithm system.
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2"
            side: Order side ("buy" or "sell")
            quantity: Amount to trade
            duration: Duration to monitor for optimal price in seconds
            client_algo_id: Unique identifier for the order
            instrument_type: Optional instrument type
            
        Returns:
            Dictionary with order status and details
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}
            
            # Import here to avoid circular dependencies
            from gq_oems_py.algorithms.LimitEdgeAlgorithm import place_limit_edge_algo
            
            # Generate a client_algo_id if not provided
            if not client_algo_id:
                client_algo_id = f"limit_edge_{int(time.time())}_{symbol.replace('/', '')}"
            
            logger.info(f"Placing limit edge algo: {symbol} {side} {quantity} with duration {duration}s (client_algo_id: {client_algo_id})")
                
            # Set exchange name and account name for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")
                    
            # Register algorithm update callback if needed
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []
                    
            # Register order update callback if needed
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []
                    
            # Store order in limit_orders dictionary to track its status
            self.limit_orders[client_algo_id] = {
                'algo_type': 'limit_edge',
                'symbol': symbol,
                'side': side,
                'quantity': quantity,
                'duration': duration,
                'status': 'new',
                'start_time': time.time(),
                'client_algo_id': client_algo_id,
                'instrument_type': instrument_type,
            }
                    
            # Forward to the algorithm system
            result = await place_limit_edge_algo(
                adapter=self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                duration=duration,
                client_algo_id=client_algo_id,
                instrument_type=instrument_type,
                price=price,
                threshold=threshold
            )
            
            # Update order status based on result
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id]['status'] = result.get('status', 'error')
                self.limit_orders[client_algo_id]['algorithm_id'] = result.get('algorithm_id')
                    
            return result
                
        except Exception as e:
            error_msg = f"Failed to place limit edge algorithm order: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return {
                "status": "error",
                "message": error_msg
            }
            
    async def _execute_limit_edge_order(
        self, 
        symbol: str, 
        side: str, 
        quantity: float, 
        duration: int, 
        client_algo_id: str,
        base_token: str,
        quote_token: str
    ) -> Dict[str, Any]:
        """
        Enhanced limit edge order execution logic:
        1. First tries to execute when price is slightly better than quoted price
        2. If no ideal price found, places a limit order at the quoted price
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2" or "TOKEN1/TOKEN2-<slippage>"
            side: Order side ("buy" or "sell")
            quantity: Amount to trade
            duration: Time in seconds to wait for optimal price before fallback
            client_algo_id: Unique identifier for the order
            base_token: Base token address
            quote_token: Quote token address
        """
        
        
        logger.info("\n" + "=" * 80)
        logger.info(f"LIMIT EDGE ORDER: {client_algo_id}")
        logger.info("-" * 80)
        
        # Extract base symbol and slippage from symbol if provided
        slippage_percentage = 0.5  # Default slippage
        base_symbol = symbol
        
        if '-' in symbol:
            base_symbol, slippage_str = symbol.rsplit('-', 1)
            try:
                slippage_percentage = float(slippage_str.strip())
                logger.info(f"Using slippage from symbol: {slippage_percentage}%")
            except ValueError:
                logger.warning(f"Invalid slippage value in symbol: {slippage_str}. Using default 0.5%")
        
        logger.info(f"Symbol      : {base_symbol}")
        logger.info(f"Side        : {side.upper()}")
        logger.info(f"Quantity    : {quantity}")
        logger.info(f"Wait Period : {duration} seconds")
        logger.info(f"Slippage    : {slippage_percentage}%")
        
        try:
            # Get initial price information for the exact quantity
            initial_price_info = await self._fetch_current_price(base_symbol, target_amount=quantity)
            if not initial_price_info:
                return {
                    "status": "error",
                    "message": f"Failed to fetch initial price for {base_symbol}"
                }

            # Find matching quote for our exact quantity
            initial_quoted_price = None
            for quote in initial_price_info.get("quotes", []):
                if abs(quote["amount_in"] - quantity) < 0.0001:
                    initial_quoted_price = quote["price"]
                    break

            if initial_quoted_price is None:
                return {
                    "status": "error",
                    "message": f"No quote available for quantity {quantity}"
                }

            logger.info(f"Initial Quoted Price: {initial_quoted_price:.8f}")
            logger.info(f"Slippage Percentage: {slippage_percentage}%")

            # Calculate optimal price target based on side
            if side.lower() == "buy":
                # For buy, we want a price better (lower) than quoted
                optimal_price = initial_quoted_price * (1 - slippage_percentage/100)
                logger.info(f"Optimal Target: {optimal_price:.8f} (Quote - {slippage_percentage}%)")
            else:
                # For sell, we want a price better (higher) than quoted
                optimal_price = initial_quoted_price * (1 + slippage_percentage/100)
                logger.info(f"Optimal Target: {optimal_price:.8f} (Quote + {slippage_percentage}%)")

            # Store the order with additional information
            self.limit_orders[client_algo_id] = {
                "symbol": base_symbol,  # Store base symbol without slippage
                "side": side,
                "quantity": quantity,
                "slippage": slippage_percentage,  # Store extracted slippage
                "base_token": base_token,
                "quote_token": quote_token,
                "quoted_price": initial_quoted_price,
                "optimal_price": optimal_price,
                "algo_type": "limit_edge",
                "status": "pending",
                "start_time": time.time(),
                "end_time": time.time() + duration
            }

            logger.info("-" * 80)
            logger.info(f"Phase 1: Monitoring for optimal price for {duration} seconds")
            logger.info("=" * 80)

            # PHASE 1: Try to execute at optimal price for specified duration
            start_time = time.time()
            end_time = start_time + duration

            while time.time() < end_time:
                # Check if order was canceled
                if client_algo_id not in self.limit_orders:
                    logger.info(f"Order {client_algo_id} cancelled, stopping execution")
                    return {
                        "status": "cancelled",
                        "message": "Order was cancelled during execution"
                    }
                    
                # Get current price info
                price_info = await self._fetch_current_price(base_symbol)
                if not price_info:
                    logger.warning(f"Failed to fetch price for {base_symbol}")
                    await asyncio.sleep(2)
                    continue

                # Find current quote for our exact quantity
                current_quoted_price = None
                for quote in price_info.get("quotes", []):
                    if abs(quote["amount_in"] - quantity) < 0.0001:
                        current_quoted_price = quote["price"]
                        break

                if current_quoted_price is None:
                    logger.warning("No quote available for the given quantity")
                    await asyncio.sleep(2)
                    continue

                time_left = int(end_time - time.time())
                
                # Check if current price meets our optimal price target
                if side.lower() == "buy":
                    logger.info(f"Current Quote: {current_quoted_price:.8f}, Target: {optimal_price:.8f}, Time left: {time_left}s")
                    if current_quoted_price <= optimal_price:
                        logger.info("\n" + "=" * 80)
                        logger.info(f"✅ OPTIMAL PRICE FOUND! Executing at {current_quoted_price:.8f}")
                        logger.info("=" * 80)
                        
                        # Execute at favorable price
                        result = await self._execute_market_order(
                            symbol=base_symbol,
                            side=side,
                            quantity=quantity,
                            client_algo_id=f"{client_algo_id}-opt"
                        )
                        
                        # Update order status
                        if client_algo_id in self.limit_orders:
                            self.limit_orders[client_algo_id]["status"] = result.get("status", "executed")
                            self.limit_orders[client_algo_id]["execution_price"] = current_quoted_price
                            self.limit_orders[client_algo_id]["execution_time"] = time.time()
                            
                            # Broadcast algorithm update
                            if hasattr(self, "algo_update_callbacks") and self.algo_update_callbacks:
                                algo_update = {
                                    "algo_update": {
                                        "exchange_name": getattr(self, "exchange_name", "uniswap_v4"),
                                        "account_name": getattr(self, "account_name", "default"),
                                        "client_algo_id": client_algo_id,
                                        "algorithm_id": client_algo_id,
                                        "status": "completed",
                                        "parameters": {
                                            "algorithm_type": "limit_edge",
                                            "symbol": base_symbol,
                                            "side": side,
                                            "quantity": quantity,
                                            "duration": duration
                                        },
                                        "filled_quantity": quantity,
                                        "price": current_quoted_price,
                                        "timestamp": datetime.now().isoformat()
                                    }
                                }
                                for callback in self.algo_update_callbacks:
                                    if callable(callback):
                                        try:
                                            asyncio.create_task(callback(algo_update))
                                        except Exception as e:
                                            logger.error(f"Error in algorithm update callback: {str(e)}")
                        
                        return {
                            "status": result.get("status", "success"),
                            "message": f"Executed at optimal price: {current_quoted_price:.8f}",
                            "phase": "optimal",
                            "result": result
                        }
                else:  # sell
                    logger.info(f"Current Quote: {current_quoted_price:.8f}, Target: {optimal_price:.8f}, Time left: {time_left}s")
                    if current_quoted_price >= optimal_price:
                        logger.info("\n" + "=" * 80)
                        logger.info(f"✅ OPTIMAL PRICE FOUND! Executing at {current_quoted_price:.8f}")
                        logger.info("=" * 80)
                        
                        # Execute at favorable price
                        result = await self._execute_market_order(
                            symbol=base_symbol,
                            side=side,
                            quantity=quantity,
                            client_algo_id=f"{client_algo_id}-opt"
                        )
                        
                        # Update order status
                        if client_algo_id in self.limit_orders:
                            self.limit_orders[client_algo_id]["status"] = result.get("status", "executed")
                            self.limit_orders[client_algo_id]["execution_price"] = current_quoted_price
                            self.limit_orders[client_algo_id]["execution_time"] = time.time()
                            
                            # Broadcast algorithm update
                            if hasattr(self, "algo_update_callbacks") and self.algo_update_callbacks:
                                algo_update = {
                                    "algo_update": {
                                        "exchange_name": getattr(self, "exchange_name", "uniswap_v4"),
                                        "account_name": getattr(self, "account_name", "default"),
                                        "client_algo_id": client_algo_id,
                                        "algorithm_id": client_algo_id,
                                        "status": "completed",
                                        "parameters": {
                                            "algorithm_type": "limit_edge",
                                            "symbol": base_symbol,
                                            "side": side,
                                            "quantity": quantity,
                                            "duration": duration
                                        },
                                        "filled_quantity": quantity,
                                        "price": current_quoted_price,
                                        "timestamp": datetime.now().isoformat()
                                    }
                                }
                                for callback in self.algo_update_callbacks:
                                    if callable(callback):
                                        try:
                                            asyncio.create_task(callback(algo_update))
                                        except Exception as e:
                                            logger.error(f"Error in algorithm update callback: {str(e)}")
                        
                        return {
                            "status": result.get("status", "success"),
                            "message": f"Executed at optimal price: {current_quoted_price:.8f}",
                            "phase": "optimal",
                            "result": result
                        }

                await asyncio.sleep(2)

            # PHASE 2: If we reach here, optimal price wasn't found within duration
            # Get the final quote price to use for limit order
            logger.info("\n" + "=" * 80)
            logger.info(f"⏰ Time limit reached ({duration}s) without finding optimal price")
            logger.info("-" * 80)
            logger.info("Phase 2: Placing limit order based on current quoted price")
            logger.info("=" * 80)

            # Get final price info for limit order
            final_price_info = await self._fetch_current_price(base_symbol, target_amount=quantity)
            if not final_price_info:
                return {
                    "status": "error",
                    "message": f"Failed to fetch final price for limit order placement"
                }

            # Extract the spot price (just for logging)
            try:
                final_spot_price = float(final_price_info["price_data"]["spot_price"])
            except (KeyError, ValueError) as e:
                logger.error(f"Invalid final price_data format: {e}")
                final_spot_price = None

            # Find final quote for our exact quantity
            final_quoted_price = None
            for quote in final_price_info.get("quotes", []):
                if abs(quote["amount_in"] - quantity) < 0.0001:
                    final_quoted_price = quote["price"]
                    break
                    
            if final_quoted_price is None:
                # If no quote available, fall back to the initial quote price
                logger.warning(f"No quote available for final price, using initial quote price: {initial_quoted_price}")
                final_quoted_price = initial_quoted_price

            # Add a small premium to the quoted price to improve execution chances
            if side.lower() == "buy":
                # For buy orders, we want to pay slightly less than the quoted price
                final_limit_price = final_quoted_price - 0.01
                logger.info(f"Final Quote Price: {final_quoted_price:.8f} -> Limit Price: {final_limit_price:.8f} (Quote - 0.01)")
                if final_spot_price:
                    logger.info(f"Spot Price for reference: {final_spot_price:.8f}")
            else:
                # For sell orders, we want to receive slightly more than the quoted price
                final_limit_price = final_quoted_price + 0.01
                logger.info(f"Final Quote Price: {final_quoted_price:.8f} -> Limit Price: {final_limit_price:.8f} (Quote + 0.01)")
                if final_spot_price:
                    logger.info(f"Spot Price for reference: {final_spot_price:.8f}")

            # Place a limit order at the adjusted quoted price
            result = await self._execute_limit_order(
                symbol=base_symbol,
                side=side,
                quantity=quantity,
                price=final_limit_price,
                client_algo_id=f"{client_algo_id}-limit"
            )

            # Update original order status
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id]["status"] = "converted_to_limit"
                self.limit_orders[client_algo_id]["limit_order_id"] = f"{client_algo_id}-limit"
                self.limit_orders[client_algo_id]["limit_price"] = final_limit_price
                self.limit_orders[client_algo_id]["quoted_price_at_conversion"] = final_quoted_price
                if final_spot_price:
                    self.limit_orders[client_algo_id]["spot_price_at_conversion"] = final_spot_price
                    
                # Broadcast algorithm update for the phase transition
                if hasattr(self, "algo_update_callbacks") and self.algo_update_callbacks:
                    algo_update = {
                        "algo_update": {
                            "exchange_name": getattr(self, "exchange_name", "uniswap_v4"),
                            "account_name": getattr(self, "account_name", "default"),
                            "client_algo_id": client_algo_id,
                            "algorithm_id": client_algo_id,
                            "status": "partial",
                            "parameters": {
                                "algorithm_type": "limit_edge",
                                "symbol": base_symbol,
                                "side": side,
                                "quantity": quantity,
                                "duration": duration
                            },
                            "phase": "limit_fallback",
                            "limit_price": final_limit_price,
                            "limit_order_id": f"{client_algo_id}-limit",
                            "timestamp": datetime.now().isoformat()
                        }
                    }
                    for callback in self.algo_update_callbacks:
                        if callable(callback):
                            try:
                                asyncio.create_task(callback(algo_update))
                            except Exception as e:
                                logger.error(f"Error in algorithm update callback: {str(e)}")

            return {
                "status": result.get("status", "success"),
                "message": f"Placed limit order at adjusted quoted price: {final_limit_price:.8f} (original quote: {final_quoted_price:.8f})",
                "phase": "limit_fallback",
                "limit_order_id": f"{client_algo_id}-limit",
                "limit_price": final_limit_price,
                "quoted_price": final_quoted_price,
                "spot_price": final_spot_price,
                "result": result
            }
        except Exception as e:
            error_msg = f"Failed to execute limit edge order: {str(e)}"
            logger.error(error_msg)
            
            # Broadcast error status
            if hasattr(self, "algo_update_callbacks") and self.algo_update_callbacks:
                algo_update = {
                    "algo_update": {
                        "exchange_name": getattr(self, "exchange_name", "uniswap_v4"),
                        "account_name": getattr(self, "account_name", "default"),
                        "client_algo_id": client_algo_id,
                        "algorithm_id": client_algo_id,
                        "status": "error",
                        "parameters": {
                            "algorithm_type": "limit_edge",
                            "symbol": symbol,
                            "side": side,
                            "quantity": quantity,
                            "duration": duration
                        },
                        "error": error_msg,
                        "timestamp": datetime.now().isoformat()
                    }
                }
                for callback in self.algo_update_callbacks:
                    if callable(callback):
                        try:
                            asyncio.create_task(callback(algo_update))
                        except Exception as callback_error:
                            logger.error(f"Error in algorithm update callback: {str(callback_error)}")
            
            return {
                "status": "error",
                "message": error_msg
            }
            
    async def place_immediate_cancel_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        price: Optional[float] = None,  # Interpreted as slippage (e.g., 0.03 for 3%)
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Queue an Immediate-or-Cancel (IOC) order for execution on Uniswap V4.
        The order will be processed to execute the maximum possible quantity within the slippage tolerance,
        canceling any unfilled portion.

        Args:
            symbol: Trading pair (e.g., "USDC/LINK")
            side: Order side ("buy" or "sell")
            quantity: Amount of tokens to trade (quote token for buy, base token for sell)
            price: Slippage tolerance as a decimal (e.g., 0.03 for 3%), defaults to None (uses 0.03)
            client_algo_id: Unique identifier for the order

        Returns:
            Dict with status, message, and queue information
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}

            # Default slippage to 3% if price is None
            slippage = price if price is not None else 0.03

            # Generate client_algo_id if not provided
            if not client_algo_id:
                client_algo_id = f"ioc_{int(time.time())}"

            # Validate symbol
            token_symbols = symbol.split('/')
            if len(token_symbols) != 2:
                return {
                    "status": "error",
                    "message": f"Invalid symbol format: {symbol}. Expected format: TOKEN1/TOKEN2"
                }

            base_token, quote_token = token_symbols[0], token_symbols[1]
            if base_token not in self.token_addresses or quote_token not in self.token_addresses:
                return {
                    "status": "error",
                    "message": f"Unsupported tokens: {base_token} or {quote_token}"
                }

            # Add order to queue
            order = {
                "type": "ioc",
                "symbol": symbol,
                "side": side,
                "quantity": quantity,
                "price": slippage,  # Store as slippage
                "client_algo_id": client_algo_id,
                "timestamp": time.time()
            }

            await self.order_queue.put(order)

            logger.info(f"IOC order {client_algo_id} queued for {symbol}: {quantity} {side} with slippage {slippage*100}%")
            return {
                "status": "queued",
                "message": "IOC order added to execution queue",
                "client_algo_id": client_algo_id,
                "queue_position": self.order_queue.qsize()
            }

        except Exception as e:
            error_msg = f"Failed to queue IOC order: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }

    async def create_order(
        self, symbol: str, side: str, type: str, amount: float, price: float = None,
        client_algo_id: str = None, params: dict = None
    ) -> dict:
        """
        Create an order on Uniswap V4.
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2"
            side: Order side ("buy" or "sell")
            type: Order type ("market", "limit", etc.)
            amount: Quantity to trade
            price: Price for limit orders
            client_algo_id: Unique identifier for the order
            params: Additional parameters for specific order types
            
        Returns:
            Dictionary with order status and details
        """
        logger.info(f"Creating order: {symbol}, Side: {side}, Type: {type}, Amount: {amount}, Price: {price}")
        
        if not self.authenticated:
            return {"status": "error", "message": "Not authenticated"}
        
        # Generate a client_algo_id if not provided
        if not client_algo_id:
            import uuid
            client_algo_id = f"{type}_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        
        try:
            # Route to appropriate queue based on order type
            if type.lower() == "market":
                # Simply add the market order to the queue
                order = {
                    'type': 'market',
                    'symbol': symbol,
                    'side': side,
                    'quantity': amount,
                    'client_algo_id': client_algo_id,
                    'timestamp': time.time()
                }
                
                # Create a future to get the result
                result_future = asyncio.Future()
                
                # Define callback to resolve the future
                def resolve_future(result):
                    if not result_future.done():
                        result_future.set_result(result)
                
                # Add the callback to the order
                order["callback"] = resolve_future
                
                # Add to queue
                await self.order_queue.put(order)
                
                if not hasattr(self, "completed_orders"):
                    self.completed_orders = {}
                self.completed_orders[client_algo_id] = {
                    "status": "in_progress",
                    "filled": 0.0,
                    "remaining": amount,
                    "price": price,
                    "symbol": symbol,
                    "timestamp": int(time.time() * 1000)
                }
                return {
                    "status": "queued",
                    "message": "Market order added to execution queue",
                    "client_algo_id": client_algo_id,
                    "id": client_algo_id,  # Add this to make it compatible with algo system
                    "queue_position": self.order_queue.qsize()
                }
                
            elif type.lower() == "limit":
                if not price:
                    return {"status": "error", "message": "Price is required for limit orders"}
                
                if params and isinstance(params, dict):
                    allow_partial = params.get("allow_partial", False)
                # Call the overloaded place_limit_algo if allow_partial is True
                if allow_partial:
                    result = await self.place_limit_algo(
                        symbol=symbol,
                        side=side,
                        quantity=amount,
                        price=price,
                        client_algo_id=client_algo_id,
                        allow_partial=True
                    )
                    result["id"] = client_algo_id
                    return result
                # Otherwise, proceed as before
                order = {
                    'type': 'limit',
                    'symbol': symbol,
                    'side': side,
                    'quantity': amount,
                    'price': price,
                    'client_algo_id': client_algo_id,
                    'timestamp': time.time()
                }
                
                # Create a future to get the result
                result_future = asyncio.Future()
                
                # Define callback to resolve the future
                def resolve_future(result):
                    if not result_future.done():
                        result_future.set_result(result)
                
                # Add the callback to the order
                order["callback"] = resolve_future
                
                # Add to queue
                await self.order_queue.put(order)
                
                if not hasattr(self, "completed_orders"):
                    self.completed_orders = {}
                self.completed_orders[client_algo_id] = {
                    "status": "pending",
                    "filled": 0.0,
                    "remaining": amount,
                    "price": price,
                    "symbol": symbol,
                    "timestamp": int(time.time() * 1000)
                }
                
                return {
                    "status": "queued",
                    "message": "Limit order added to execution queue",
                    "client_algo_id": client_algo_id,
                    "id": client_algo_id,  # Add this to make it compatible with algo system
                    "queue_position": self.order_queue.qsize()
                }
            else:
                return {
                    "status": "error",
                    "message": f"Unsupported order type: {type}"
                }
        except Exception as e:
            error_msg = f"Failed to create {type} order: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }
            
    def market(self, symbol: str) -> dict:
        """
        Return market metadata for a symbol.
        """
        # If you have a self.markets dict, use it:
        if hasattr(self, "markets") and symbol in self.markets:
            return self.markets[symbol]
        # Otherwise, return a default structure (customize as needed)
        return {
            "symbol": symbol,
            "limits": {
                "cost": {"min": 0.0}
            }
        }
        
    async def get_min_quantity(self, symbol: str, side: str) -> float:
        """Return the minimum order quantity for the correct token based on side."""
        precision = await self.get_quantity_precision(symbol, side)
        if precision is None:
            return None
        return 1 / (10**precision)
            
    async def place_twap_algo(
        self, 
        symbol: str, 
        side: str, 
        quantity: float, 
        duration: int, 
        interval: int, 
        client_algo_id: str,
        instrument_type: Optional[str] = None
    ) -> dict:
        """
        Place a TWAP algorithm order using the algorithm system.
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}

            # Import here to avoid circular dependencies
            from gq_oems_py.algorithms.TwapAlgorithm import place_twap_algo

            # Set exchange name and account name for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")

            # Register algorithm update callback if needed
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []

            # Track the order in limit_orders for status
            self.limit_orders[client_algo_id] = {
                "symbol": symbol,
                "side": side,
                "quantity": quantity,
                "duration": duration,
                "interval": interval,
                "algo_type": "twap",
                "status": "new",
                "executed": 0.0,
                "client_algo_id": client_algo_id,
                "instrument_type": instrument_type
            }

            # Forward to the algorithm system
            result = await place_twap_algo(
                self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                duration=duration,
                interval=interval,
                client_algo_id=client_algo_id,
                instrument_type=instrument_type
            )

            # Update order status based on result
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id]['status'] = result.get('status', 'error')
                self.limit_orders[client_algo_id]['algorithm_id'] = result.get('algorithm_id')

            return result

        except Exception as e:
            error_msg = f"Failed to start TWAP order: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg,
                "client_algo_id": client_algo_id
            }
    
    
    async def place_trailing_stop_loss_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        trail_percent: float,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
    ) -> dict:
        """
        Place a Trailing Stop Loss algorithm order using the algorithm system.
        
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2"
            side: Order side ("buy" or "sell")
            quantity: Amount to trade
            trail_percent: Percentage to trail market price
            client_algo_id: Unique identifier for the order
            instrument_type: Optional instrument type
            
        Returns:
            Dictionary with order status and details
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}
            
            # Import here to avoid circular dependencies
            from gq_oems_py.algorithms.TSLAlgorithm import place_trailing_stop_loss_algo
            
            # Generate a client_algo_id if not provided
            if not client_algo_id:
                client_algo_id = f"tsl_{int(time.time())}_{symbol.replace('/', '')}"
            
            logger.info(f"Placing trailing stop loss algo: {symbol} {side} {quantity} with trail_percent {trail_percent}% (client_algo_id: {client_algo_id})")
                
            # Set exchange name and account name for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")
                    
            # Register algorithm update callback if needed
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []
                    
            # Register order update callback if needed
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []
                    
            # Store order in limit_orders dictionary to track its status
            self.limit_orders[client_algo_id] = {
                'algo_type': 'trailing_stop_loss',
                'symbol': symbol,
                'side': side,
                'quantity': quantity,
                'trail_percent': trail_percent,
                'status': 'new',
                'start_time': time.time(),
                'client_algo_id': client_algo_id,
                'instrument_type': instrument_type,
            }
                    
            # Forward to the algorithm system
            result = await place_trailing_stop_loss_algo(
                exchange=self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                trail_percent=trail_percent,
                client_algo_id=client_algo_id
            )
            
            # Update order status based on result
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id]['status'] = result.get('status', 'error')
                self.limit_orders[client_algo_id]['algorithm_id'] = result.get('algorithm_id')
                    
            return result
                
        except Exception as e:
            error_msg = f"Failed to place trailing stop loss algorithm order: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return {
                "status": "error",
                "message": error_msg
            }
        
    
    async def place_day_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        price: float,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
    ) -> dict:
        """
        Place a day algorithm order using the algorithm system.
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}

            # Import here to avoid circular dependencies
            from gq_oems_py.algorithms.DayAlgorithm import place_day_algo

            # Generate a client_algo_id if not provided
            if not client_algo_id:
                client_algo_id = f"day_{int(time.time())}_{symbol.replace('/', '')}"

            logger.info(
                f"Placing day algo: {symbol} {side} {quantity} at {price} (client_algo_id: {client_algo_id})"
            )

            # Set exchange name and account name for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")

            # Register algorithm update callback if needed
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []

            # Register order update callback if needed
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []

            # Store order in limit_orders dictionary to track its status
            self.limit_orders[client_algo_id] = {
                'algo_type': 'day',
                'symbol': symbol,
                'side': side,
                'quantity': quantity,
                'price': price,
                'status': 'new',
                'start_time': time.time(),
                'client_algo_id': client_algo_id,
                'instrument_type': instrument_type,
            }

            # Forward to the algorithm system
            result = await place_day_algo(
                adapter=self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                price=price,
                client_algo_id=client_algo_id,
                instrument_type=instrument_type,
            )

            # Update order status based on result
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id]['status'] = result.get('status', 'error')
                self.limit_orders[client_algo_id]['algorithm_id'] = result.get('algorithm_id')

            return result

        except Exception as e:
            error_msg = f"Failed to place day algorithm order: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return {
                "status": "error",
                "message": error_msg
            }
                
    async def place_good_till_time_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        price: float,
        expiry_time: int,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
    ) -> dict:
        """
        Place a Good-Till-Time (GTT) algorithm order using the algorithm system.
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}

            from gq_oems_py.algorithms.GoodTillTimeAlgorithm import place_good_till_time_algo

            # Generate a client_algo_id if not provided
            if not client_algo_id:
                client_algo_id = f"gtt_{int(time.time())}_{symbol.replace('/', '')}"

            logger.info(
                f"Placing GTT algo: {symbol} {side} {quantity} at {price} until {expiry_time} (client_algo_id: {client_algo_id})"
            )

            # Set exchange name and account name for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")

            # Register algorithm update callback if needed
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []

            # Register order update callback if needed
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []

            # Store order in limit_orders dictionary to track its status
            self.limit_orders[client_algo_id] = {
                'algo_type': 'good_till_time',
                'symbol': symbol,
                'side': side,
                'quantity': quantity,
                'price': price,
                'expiry_time': expiry_time,
                'status': 'new',
                'start_time': time.time(),
                'client_algo_id': client_algo_id,
                'instrument_type': instrument_type,
            }

            # Forward to the algorithm system
            result = await place_good_till_time_algo(
                adapter=self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                price=price,
                expiry_time=expiry_time,
                client_algo_id=client_algo_id,
                instrument_type=instrument_type,
            )

            # Update order status based on result
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id]['status'] = result.get('status', 'error')
                self.limit_orders[client_algo_id]['algorithm_id'] = result.get('algorithm_id')

            return result

        except Exception as e:
            error_msg = f"Failed to place Good-Till-Time algorithm order: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return {
                "status": "error",
                "message": error_msg
            }
                
    def broadcast_order_update(self, algo_id: str, client_algo_id: str, symbol: str, 
                            order_id: Optional[str], status: str, filled: float, 
                            remaining: float, price: Optional[float], 
                            exchange_order_data: Any = None) -> None:
        """
        Broadcast an order update to all registered callbacks.
        
        Args:
            algo_id: Algorithm ID
            client_algo_id: Client algorithm ID
            symbol: Trading symbol
            order_id: Order ID (can be None for rejected orders)
            status: Order status
            filled: Filled quantity
            remaining: Remaining quantity
            price: Order price
            exchange_order_data: Exchange-specific order data
        """
        try:
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4_test"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")
                
            # Create the order update in the expected format
            order_update = {
                "order_update": {
                    "exchange_name": self.exchange_name,
                    "account_name": self.account_name,
                    "algorithm_id": algo_id,
                    "client_algo_id": client_algo_id,
                    "order_id": order_id or "",
                    "symbol": symbol,
                    "status": status,
                    "filled": filled,
                    "remaining": remaining,
                    "price": price,
                    "timestamp": datetime.now().isoformat(),
                    "exchange_order_update": exchange_order_data
                }
            }
            
            # Broadcast to registered callbacks
            if hasattr(self, "order_update_callbacks"):
                for callback in self.order_update_callbacks:
                    if callable(callback):
                        try:
                            asyncio.create_task(callback(order_update))
                        except Exception as e:
                            logger.error(f"Error in order update callback: {e}")
            else:
                logger.debug("No order update callbacks registered")
                
        except Exception as e:
            logger.error(f"Error broadcasting order update: {e}")
                           

    async def fetch_positions(self) -> dict:
        return {}

    async def watch_order(self, order_id: str, symbol: str):
        """
        Watch for updates to an order and yield them as they arrive
        
        Args:
            order_id: Order ID to watch
            symbol: Symbol for the order
            
        Yields:
            Order status updates
        """
        try:
            logger.info(f"Starting to watch order {order_id} for {symbol}")
            check_interval = 1.0  # Check once per second
            
            # Initial check
            order_info = await self.fetch_order(order_id, symbol)
            
            # call the broadcast order update funciton
            self.broadcast_order_update(
                algo_id=order_info.get("algo_id", ""),
                client_algo_id=order_info.get("client_algo_id", order_id),
                symbol=symbol,
                order_id=order_info.get("id"),
                status=order_info.get("status", "unknown"),
                filled=order_info.get("filled", 0.0),
                remaining=order_info.get("remaining", 0.0),
                price=order_info.get("price"),
                exchange_order_data=order_info
            )
            
            yield order_info
            
            previous_status = order_info.get("status")
            previous_filled = order_info.get("filled", 0)
            
            # Continue checking until we reach a terminal state
            while order_info.get("status") not in ["filled", "canceled", "cancelled", "rejected", "error"]:
                await asyncio.sleep(check_interval)
                
                # Check if order was cancelled
                # Only treat as canceled if not in completed_orders at all
                if order_id not in self.limit_orders and order_id not in getattr(self, "completed_orders", {}):
                    logger.info(f"Order {order_id} not found in active or completed orders, assuming cancelled")
                    yield {
                        "id": order_id,
                        "status": "canceled",
                        "filled": previous_filled,
                        "remaining": order_info.get("quantity", 0) - previous_filled,
                        "price": order_info.get("price"),
                        "symbol": symbol,
                        "timestamp": int(time.time() * 1000)
                    }
                    break
                
                # Fetch updated order info
                order_info = await self.fetch_order(order_id, symbol)
                current_status = order_info.get("status")
                current_filled = order_info.get("filled", 0)
                
                # Only yield if something has changed
                if (current_status != previous_status) or (current_filled != previous_filled):
                    logger.debug(f"Order {order_id} update: {current_status}, filled: {current_filled}")
                    yield order_info
                    
                    previous_status = current_status
                    previous_filled = current_filled
                
                # Exit if we've reached a terminal state
                if current_status in ["filled", "canceled", "cancelled", "rejected", "error"]:
                    logger.info(f"Order {order_id} reached terminal state: {current_status}")
                    break
        
        except Exception as e:
            logger.error(f"Error watching order {order_id}: {str(e)}")
            # Yield an error status
            yield {
                "id": order_id,
                "status": "error",
                "error": str(e),
                "symbol": symbol,
                "timestamp": int(time.time() * 1000)
            }
            
    async def place_twap_edge_algo(
        self, 
        symbol: str, 
        side: str, 
        quantity: float, 
        duration: int, 
        interval: int, 
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Place a TWAP Edge algorithm order using the algorithm system.
        
        TWAP Edge combines limit orders (for better pricing) with market orders 
        (for guaranteed execution) in time-sliced intervals.
        """
        try:
            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}

            # Import here to avoid circular dependencies
            from gq_oems_py.algorithms.TwapEdgeAlgorithm import place_twap_edge_algo

            # Generate a client_algo_id if not provided
            if not client_algo_id:
                client_algo_id = f"twap_edge_{int(time.time())}_{symbol.replace('/', '')}"
            
            logger.info(f"Placing TWAP Edge algo: {symbol} {side} {quantity} duration={duration}s interval={interval} (client_algo_id: {client_algo_id})")
                
            # Set exchange name and account name for algo updates
            if not hasattr(self, "exchange_name"):
                self.exchange_name = "uniswap_v4"
            if not hasattr(self, "account_name"):
                self.account_name = getattr(self, "account_name", "default")
                
            # Register algorithm update callback if needed
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []
                
            # Register order update callback if needed
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []
                
            # Store order in limit_orders dictionary to track its status
            self.limit_orders[client_algo_id] = {
                'algo_type': 'twap_edge',
                'symbol': symbol,
                'side': side,
                'quantity': quantity,
                'duration': duration,
                'interval': interval,
                'status': 'new',
                'start_time': time.time(),
                'client_algo_id': client_algo_id,
                'instrument_type': instrument_type,
            }
                
            # Forward to the algorithm system
            result = await place_twap_edge_algo(
                exchange=self,
                symbol=symbol,
                side=side,
                quantity=quantity,
                duration=duration,
                interval=interval,
                client_algo_id=client_algo_id,
                instrument_type=instrument_type
            )
            
            # Update order status based on result
            if client_algo_id in self.limit_orders:
                self.limit_orders[client_algo_id]['status'] = result.get('status', 'error')
                self.limit_orders[client_algo_id]['algorithm_id'] = result.get('algorithm_id')

            return result
            
        except Exception as e:
            error_msg = f"Failed to place TWAP Edge algorithm order: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return {
                "status": "error",
                "message": error_msg,
                "client_algo_id": client_algo_id
            }
            

    async def initialize_minimum_quantity(self) -> float:
        """
        Initialize the minimum quantity for TWAP Edge compatibility.

        Returns:
            float: The minimum quantity value.
        """
        logger.info("Initializing minimum quantity for TWAP Edge compatibility.")
        return 0.05
            
    async def close(self) -> None:
        pass
    
    async def fetch_order_book(self, symbol: str) -> Dict[str, Any]:
        """
        Stub out orderbook calls for MarketEdgeAlgorithm—
        UniswapV4Adapter is ticker-only.
        """
        return {"bids": [], "asks": []}


    async def liquidate_all_positions(self) -> dict:
        return {}


    async def place_edge_algo(self, symbol: str, side: str, quantity: float, client_algo_id: str, llambda: float = None, alpha: float = None, beta: float = None, gamma: float = None, eta: float = None, epsilon: float = None, number_of_trades: int = None, transaction_time: float = None) -> dict:
        raise NotImplementedError("place_edge_algo not implemented for UniswapV4Adapter")
    
    
    async def get_quantity_precision(self, symbol: str, side: str = None) -> int:
        # symbol is like "LINK/USDC"
        base_symbol = symbol.split('/')[0]
        token_address = self.token_addresses[base_symbol]
        return await self.get_token_decimals(token_address)
    
    
    async def estimate_volume_from_liquidity(self, symbol: str) -> float:
        """
        Estimate the 24h trading volume of a Uniswap V4 pool using on-chain liquidity and spot price.
        Args:
            symbol: Trading pair in format "TOKEN1/TOKEN2" (e.g., "WETH/USDC")
        Returns:
            Estimated 24h volume in base token units (float)
        """
        try:
            base_symbol, quote_symbol = symbol.upper().split('/')
            base = Web3.to_checksum_address(self.token_addresses[base_symbol])
            quote = Web3.to_checksum_address(self.token_addresses[quote_symbol])
            fee = 3000
            tick_spacing = 60
            hooks = Web3.to_checksum_address('0x0000000000000000000000000000000000000000')

            # Always sort for Uniswap pool ordering
            token0, token1 = sorted([base, quote])
            pool_id = Web3.keccak(abi_encode(
                ['address', 'address', 'uint24', 'int24', 'address'],
                [token0, token1, fee, tick_spacing, hooks]
            ))

            # Fetch liquidity from the pool manager contract
            # Uniswap V4 pool manager exposes getSlot0 and getLiquidity
            liquidity = self.state_view.functions.getLiquidity(pool_id).call()

            # Fetch spot price using the same logic as _fetch_current_price
            sqrt_price_x96, _, _, _ = self.state_view.functions.getSlot0(pool_id).call()
            raw_price = (sqrt_price_x96 / (2**96)) ** 2
            decimals0 = await self.get_token_decimals(token0)
            decimals1 = await self.get_token_decimals(token1)
            price_token1_per_token0 = raw_price * (10 ** (decimals0 - decimals1))
            spot_price = (
                price_token1_per_token0
                if base == token0 and quote == token1
                else 1 / price_token1_per_token0
            )

            # Heuristic: volume ≈ liquidity * spot_price * turnover_ratio
            # turnover_ratio is a guess; 0.5 means 50% of liquidity turns over in 24h
            turnover_ratio = 0.5
            est_volume = float(liquidity) * float(spot_price) * turnover_ratio
            logger.info(f"ESTIMATED 24H VOLUME for {symbol}: {est_volume:.2f} {base_symbol}")
            return est_volume
        except Exception as e:
            logger.error(f"Failed to estimate volume from liquidity for {symbol}: {e}")
            return 0.0

    async def place_vwap_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        duration: int,
        max_participation_rate: float,
        unfilled_action: str,
        client_algo_id: str,
        instrument_type: Optional[str] = None,
    ) -> dict:
        """
        Place a VWAP algorithm order using the algorithm system.
        """
        try:
            from gq_oems_py.algorithms.VwapAlgorithm import place_vwap_algo

            if not self.authenticated:
                return {"status": "error", "message": "Not authenticated"}

            # Ensure callback lists are initialized
            if not hasattr(self, "order_update_callbacks"):
                self.order_update_callbacks = []
            if not hasattr(self, "algo_update_callbacks"):
                self.algo_update_callbacks = []

            # Call the VWAP algorithm with the correct parameter order
            result = await place_vwap_algo(
                self,
                symbol,
                side,
                quantity,
                duration,
                max_participation_rate,
                unfilled_action,
                client_algo_id,
                instrument_type,
            )
            return result

        except Exception as e:
            logger.error(f"VWAP algorithm error: {str(e)}", exc_info=True)
            return {
                "status": "error",
                "message": str(e),
                "client_algo_id": client_algo_id,
            }
    
    async def calculate_token_value_in_usdc(self, token_symbol: str, amount: float=1.0) -> Optional[float]:
        """
        Calculate the value of a token amount in USDC using DefiLlama API.
        
        Args:
            token_symbol: Symbol of the token (e.g., "WETH", "LINK")
            amount: Amount of tokens to calculate value for (default: 1.0)
            
        Returns:
            The value in USDC, or None if calculation fails
        """
        try:
            # If already USDC, return the amount directly
            if token_symbol.upper() == "USDC":
                return amount

            # Check if token exists in our mainnet addresses
            if token_symbol.upper() not in self.mainnet_token_addresses:
                logger.warning(f"Token {token_symbol} not found in mainnet token addresses")
                return None

            token_address = self.mainnet_token_addresses[token_symbol.upper()]
            chain = "ethereum"
            url = f"https://coins.llama.fi/prices/current/{chain}:{token_address}"
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=10.0)
                response.raise_for_status()
                data = response.json()

            coin_key = f"{chain}:{token_address}"
            if "coins" in data and coin_key in data["coins"]:
                usd_price = float(data["coins"][coin_key]["price"])
                usdc_value = amount * usd_price
                logger.debug(f"{amount} {token_symbol} = {usdc_value:.6f} USDC (via DefiLlama API)")
                return usdc_value
            else:
                logger.warning(f"Price not found for {coin_key} in DefiLlama response")
                return None
        except Exception as e:
            logger.error(f"Error calculating {token_symbol} value in USDC (DefiLlama): {e}")
            return None
    
    async def place_target_position_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        client_algo_id: str,
        instrument_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Place a target position algorithm order"""
        raise NotImplementedError("place_target_position_algo not implemented for UniswapV4Adapter")
    
    async def place_fill_or_kill_algo(
    self,
    symbol: str,
    side: str,
    quantity: float,
    price: Optional[float] = None,
    client_algo_id: str = None,
    instrument_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Place a Fill-or-Kill (FOK) algorithm order.
        This is a placeholder implementation - FOK not yet supported for UniswapV4Adapter.
        """
        raise NotImplementedError("place_fill_or_kill_algo not implemented for UniswapV4Adapter")


    async def place_smart_order_routing_algo(
        self,
        symbol: str,
        side: str,
        quantity: float,
        client_algo_id: str = None,
        instrument_type: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Place a Smart Order Routing (SOR) algorithm order.
        This is a placeholder implementation - SOR not yet supported for UniswapV4Adapter.
        """
        raise NotImplementedError("place_smart_order_routing_algo not implemented for UniswapV4Adapter")