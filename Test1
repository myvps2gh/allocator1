import os, time, json, csv, datetime, threading, argparse, logging
from collections import defaultdict
from threading import Lock
from pathlib import Path
from decimal import Decimal
import secrets
from flask import Flask, render_template_string
from web3 import Web3
from web3.exceptions import TransactionNotFound, BlockNotFound
# web3.py v7.x style
from web3.middleware import ExtraDataToPOAMiddleware
#from web3.middleware.signing import construct_sign_and_send_raw_middleware


from eth_account import Account
from cryptography.fernet import Fernet

# ------------------ LOGGING SETUP ------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("allocator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("allocator")

# =======================================
# Whale Scoring + Culling System
# =======================================
from collections import deque, defaultdict
from decimal import Decimal
import statistics

# keep short history per whale
WHALE_HISTORY = defaultdict(lambda: deque(maxlen=50))
WHALE_SCORES  = defaultdict(lambda: {"score": Decimal("0"), "roi": Decimal("0")})

def update_whale_score(whale, pnl_eth: Decimal):
    """
    Update whale performance after a mirrored trade settles.
    Automatically adjusts score & ROI.
    """
    WHALE_HISTORY[whale].append(pnl_eth)

    # calculate cumulative stats
    pnl_list = list(WHALE_HISTORY[whale])
    total_pnl = sum(pnl_list)
    win_rate  = sum(1 for x in pnl_list if x > 0) / len(pnl_list)

    # variance of results (stability measure)
    if len(pnl_list) > 1:
        stdev = statistics.pstdev([float(x) for x in pnl_list])
    else:
        stdev = 1

    # sharper whales = high pnl + consistent win rate
    score = (total_pnl * Decimal(str(win_rate))) / Decimal(str(stdev))

    WHALE_SCORES[whale] = {
        "score": score,
        "roi": Decimal(total_pnl),
        "trades": len(pnl_list),
    }
    return WHALE_SCORES[whale]

def should_follow(whale):
    """
    Decision rule whether whale stays tracked.
    Drop if ROI negative, winrate <0.4, or score falls off cliff.
    """
    stats = WHALE_SCORES.get(whale, None)
    if not stats:
        return True

    if stats["roi"] < 0:
        return False
    if stats["winrate"] < 0.4:
        return False
    if stats["score"] < 0:
        return False

    return True

def rank_whales(top_n=10):
    """Return top N whales by score"""
    ranked = sorted(WHALE_SCORES.items(), key=lambda kv: kv[1]["score"], reverse=True)
    return ranked[:top_n]


# ------------------ CLI ARGS ------------------
parser = argparse.ArgumentParser()
parser.add_argument("--test", action="store_true", help="Run in TEST_MODE (simulate trades only)")
parser.add_argument("--config", type=str, default="config.json", help="Path to configuration file")
parser.add_argument("--dry-run", action="store_true", help="Monitor but don't execute trades")
parser.add_argument("--dry-run-mempoolhack", action="store_true",help="Disable real mempool, fetch confirmed blocks >
args = parser.parse_args()
TEST_MODE = args.test
DRY_RUN = args.dry_run
DRY_RUN_MEMPOOLHACK = args.dry_run_mempoolhack

# ------------------ SECURE CONFIG LOADING ------------------
def load_config(config_path):
    try:
        with open(config_path) as f:
            config = json.load(f)

        # Validate required fields — keystore_path removed
        required_fields = [
            "web3_rpc", "tracked_whales", "capital",
            "base_risk", "max_slippage", "min_profit", "gas_boost"
        ]
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required config field: {field}")

        return config
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        raise

config = load_config(args.config)


# ------------------ SECURE WALLET LOADING (wallet.json aware) ------------------

def get_keystore_password():
    # Prefer env var
    env_password = os.environ.get("WALLET_PASS")
    if env_password:
        return env_password

    # Or fall back to password file
    password_file = os.environ.get("PASSWORD_FILE")
    if password_file and os.path.exists(password_file):
        with open(password_file, "r") as f:
            return f.read().strip()

    raise ValueError("No wallet password provided via WALLET_PASS or PASSWORD_FILE")

def load_wallet():
    """
    Load wallet from wallet.json using WALLET_PASS,
    or fallback to PRIVATE_KEY if keystore isn't present.
    Returns (wallet_address, None, private_key_hex)
    """
    try:
        # Prefer keystore
        if os.path.exists("wallet.json"):
            with open("wallet.json") as f:
                keyfile = json.load(f)

            password = get_keystore_password()
            private_key_bytes = Account.decrypt(keyfile, password)
            #private_key = private_key_bytes.hex()  # store as hex

            #account = Account.from_key(private_key)
            account = Account.from_key(private_key_bytes)
            wallet_address = account.address
            logger.info(f"[Wallet] Loaded {wallet_address} from wallet.json")

            return wallet_address, None, private_key_bytes

        # Fallback: raw env key
        raw_key = os.environ.get("PRIVATE_KEY")
        if not raw_key:
            raise RuntimeError("No wallet.json and no PRIVATE_KEY set")

        account = Account.from_key(raw_key)
        wallet_address = account.address
        logger.warning(f"[Wallet] Using naked key for {wallet_address}")

        return wallet_address, None, raw_key

    except Exception as e:
        logger.error(f"Failed to load wallet: {e}")
        raise


# ------------------ WEB3 + WALLET INIT ------------------

def setup_web3():
    """
    Setup Web3 connection and load wallet.
    Returns (w3, wallet_address, private_key_hex).
    """
    # RPC connect
    w3 = Web3(Web3.HTTPProvider(config["web3_rpc"]))

    # Inject PoA fix (needed on Sepolia, Görli, BSC etc)
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    # Load wallet
    wallet_address, _, priv_key = load_wallet()

    # Validate RPC is alive
    if not w3.is_connected():
        raise ConnectionError(f"RPC connection failed: {config['web3_rpc']}")

    logger.info(f"[Web3] Connected to chain_id={w3.eth.chain_id}")
    logger.info(f"[Web3] Wallet: {wallet_address}")

    return w3, wallet_address, priv_key



# secure key manager for priv key
def create_secure_key_manager(private_key: bytes):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted = cipher.encrypt(private_key)

    def get_key():
        return cipher.decrypt(encrypted)

    return get_key


# ---- Global Init ----
w3, WALLET_ADDR, MY_PRIVKEY = setup_web3()
secure_key_manager = create_secure_key_manager(MY_PRIVKEY)
#PRIVATE_KEY = secure_key_manager()  # when TxManager needs to sign
MY_PRIVKEY = None  # nuke raw reference
#txmgr = TxManager(w3, secure_key_manager, WALLET_ADDR)


# ------------------ CONTRACTS ------------------
UNISWAP_V2      = Web3.to_checksum_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
UNISWAP_V3      = Web3.to_checksum_address("0xE592427A0AEce92De3Edee1F18E0157C05861564")
UNISWAP_V3_QUOTER = Web3.to_checksum_address("0x61fFE014bA17989E743c5F6cB21bF9697530B21e")
BALANCER_VAULT  = Web3.to_checksum_address("0xBA12222222228d8Ba445958a75a0704d566BF2C8")
WETH            = Web3.to_checksum_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")

# ------------------ ABI LOADING ------------------
def load_abi(name):
    path = os.path.join("abis", f"{name}.json")
    with open(path) as f:
        return json.load(f)

# Cache ABIs
V2_ABI      = load_abi("uniswap_v2_router")
V3_ABI      = load_abi("uniswap_v3_router")
QUOTER_ABI  = load_abi("uniswap_v3_quoter")
BALANCER_ABI= load_abi("balancer_v2_vault")
ERC20_ABI   = load_abi("erc20")

# ------------------ CONTRACT OBJECTS ------------------
uni_v2      = w3.eth.contract(address=UNISWAP_V2, abi=V2_ABI)
uni_v3      = w3.eth.contract(address=UNISWAP_V3, abi=V3_ABI)
quoter      = w3.eth.contract(address=UNISWAP_V3_QUOTER, abi=QUOTER_ABI)
balancer    = w3.eth.contract(address=BALANCER_VAULT, abi=BALANCER_ABI)


# ------------------ TOKEN HANDLING ------------------

# Cache for ERC20 contracts + metadata
token_cache = {}
ERC20_ABI = load_abi("erc20")

def get_token(address: str):
    """Return cached token contract and metadata for an address."""
    addr = Web3.to_checksum_address(address)

    if addr in token_cache:
        return token_cache[addr]

    try:
        contract = w3.eth.contract(address=addr, abi=ERC20_ABI)

        # Safe fetch metadata
        try:
            decimals = contract.functions.decimals().call()
        except:
            decimals = 18  # sane default

        try:
            symbol = contract.functions.symbol().call()
        except:
            # fallback: truncated address tag
            symbol = addr[:6] + "…" + addr[-4:]

        meta = {
            "contract": contract,
            "decimals": decimals,
            "symbol": symbol,
            "address": addr
        }

        token_cache[addr] = meta
        logger.debug(f"[Token] Cached {symbol} ({addr}) with {decimals} decimals")

        return meta

    except Exception as e:
        logger.error(f"Token init failed for {address}: {e}")
        return {"contract": None, "decimals": 18, "symbol": "UNK", "address": addr}

def format_amount(raw_amount, decimals):
    """Convert raw onchain integer to human float."""
    return raw_amount / (10 ** decimals)


# ------------------ CONFIGURATION ------------------
capital = Decimal(str(config["capital"]))
BASE_RISK = Decimal(str(config["base_risk"]))
MAX_SLIPPAGE = Decimal(str(config["max_slippage"]))  # e.g., 0.01 for 1%
MIN_PROFIT_THRESHOLD = Decimal(str(config["min_profit"]))  # e.g., 0.005 for 0.5%
GAS_BOOST = Decimal(str(config["gas_boost"]))  # e.g., 1.1 for 10% gas boost

# Load tracked whales from config
tracked_whales = {Web3.to_checksum_address(address) for address in config["tracked_whales"]}

# Initialize token pairs we're interested in
MONITORED_TOKENS = set()
if "monitored_tokens" in config:
    MONITORED_TOKENS = {Web3.to_checksum_address(address) for address in config["monitored_tokens"]}

# Trading state
my_pnl = defaultdict(Decimal)
risk_mult = defaultdict(lambda: Decimal('1.0'))
trade_history = []
MAX_HISTORY_LENGTH = 1000

# Create log directory
log_dir = Path(config.get("log_dir", "logs"))
log_dir.mkdir(exist_ok=True)
LOGFILE = log_dir / config.get("logfile", "tradelog.csv")

# Initialize CSV log file
if not LOGFILE.exists():
    with open(LOGFILE, "w", newline="") as f:
        csv.writer(f).writerow([
            "timestamp", "actor", "whale", "router", "path", "side",
            "amount_in", "amount_out", "token_in", "token_out",
            "price_impact", "gas_cost", "pnl", "cum_pnl", "risk_mult", "mode", "tx_hash"
        ])

# ------------------ TRADE LOGGING ------------------

def log_trade(actor, whale, router, path, side, amt_in, amt_out, token_in="ETH", token_out="TOKEN",
              price_impact=0, gas_cost=0, pnl=0, tx_hash=None):
    """Log trade details to CSV and memory"""
    timestamp = datetime.datetime.utcnow().isoformat()

    # Update state
    if actor == "allocator":
        my_pnl[whale] += Decimal(str(pnl))
        # Dynamic risk adjustment based on performance
        if my_pnl[whale] > 0:
            # Increase risk for profitable whales, capped at 3x
            risk_mult[whale] = min(Decimal('3.0'), Decimal('1.0') + (my_pnl[whale] / Decimal('1000')))
                                                                                                                    >
        else:
            # Reduce risk for unprofitable whales, floor at 0.25x
            risk_mult[whale] = max(Decimal('0.25'), Decimal('1.0') + (my_pnl[whale] / Decimal('1000')))

        # NEW: update whale score stats
        update_whale_score(whale, Decimal(str(pnl)))

    # Prepare data for logging
    path_str = " -> ".join(path) if isinstance(path, list) else path
    row = [
        timestamp, actor, whale, router, path_str, side,
        round(float(amt_in), 6), round(float(amt_out), 6),
        token_in, token_out, round(float(price_impact), 6),
        round(float(gas_cost), 6), round(float(pnl), 6),
        round(float(my_pnl[whale]), 6), round(float(risk_mult[whale]), 3),

        "TEST" if TEST_MODE else ("DRY" if DRY_RUN else ("DRY_MEMPOOLHACK" if DRY_RUN_MEMPOOLHACK else "LIVE")),
        tx_hash or "N/A"
    ]

    # Write to CSV
    with open(LOGFILE, "a", newline="") as f:
        csv.writer(f).writerow(row)

    # Keep in memory for dashboard
    trade_history.append({
        "timestamp": timestamp,
        "actor": actor,
        "whale": whale,
        "router": router,
        "path": path_str,
        "side": side,
        "amount_in": float(amt_in),
        "amount_out": float(amt_out),
        "token_in": token_in,
        "token_out": token_out,
        "price_impact": float(price_impact),
        "gas_cost": float(gas_cost),
        "pnl": float(pnl),
        "cum_pnl": float(my_pnl[whale]),
        "risk_mult": float(risk_mult[whale]),
        "mode": "TEST" if TEST_MODE else ("DRY" if DRY_RUN else ("DRY_MEMPOOLHACK" if DRY_RUN_MEMPOOLHACK else "LIVE>
        "tx_hash": tx_hash or "N/A"
    })

    # Trim history if too long
    if len(trade_history) > MAX_HISTORY_LENGTH:
        trade_history.pop(0)

    logger.info(
        f"[{actor.upper()}|{whale}] {side} {float(amt_in):.4f} {token_in} → {float(amt_out):.4f} {token_out} "
        f"| impact={float(price_impact):.2%} gas={float(gas_cost):.4f} pnl={float(pnl):.4f} "
        f"cum={float(my_pnl[whale]):.4f} risk={float(risk_mult[whale]):.2f} "
        f"mode={'TEST' if TEST_MODE else ('DRY' if DRY_RUN else ('DRY_MEMPOOLHACK' if DRY_RUN_MEMPOOLHACK else 'LIVE>
    )

# ------------------ TRANSACTION PARSING ------------------
def decode_input_data(router_contract, tx_input):
    """Decode transaction input data to determine trade details"""
    try:
        func_obj, func_params = router_contract.decode_function_input(tx_input)
        return func_obj.fn_name, func_params
    except Exception as e:
        logger.debug(f"Failed to decode input: {e}")
        return None, None

def get_token_path_from_tx(router, tx_input):
    """Extract token path from transaction input"""
    if router.lower() == UNISWAP_V2.lower():
        try:
            func_name, params = decode_input_data(uni_v2, tx_input)
            if func_name and 'path' in params:
                return params['path']
        except Exception as e:
            logger.debug(f"Failed to extract path from V2: {e}")

    elif router.lower() == UNISWAP_V3.lower():
        try:
            func_name, params = decode_input_data(uni_v3, tx_input)
            if func_name == 'exactInputSingle' and 'params' in params:
                return [params['params'][0], params['params'][1]]
            elif func_name == 'exactInput' and 'params' in params:
                # For V3 multi-hop, would need to decode the path format
                pass
        except Exception as e:
            logger.debug(f"Failed to extract path from V3: {e}")

    return ["Unknown", "Unknown"]


def parse_v2_swaps(receipt, path=None):
    """Parse Uniswap V2 swap events from transaction receipt"""
    pool_abi = [{
        "anonymous": False, "inputs": [
            {"indexed": True, "name": "sender", "type": "address"},
            {"indexed": False, "name": "amount0In", "type": "uint256"},
            {"indexed": False, "name": "amount1In", "type": "uint256"},
            {"indexed": False, "name": "amount0Out", "type": "uint256"},
            {"indexed": False, "name": "amount1Out", "type": "uint256"},
            {"indexed": True, "name": "to", "type": "address"},
        ],
        "name": "Swap", "type": "event"
    }]

    parsed = []
    token0, token1 = None, None

    if path and len(path) >= 2:
        token0, token1 = path[0], path[-1]

    for log in receipt.logs:
        try:
            # Try to match log to Swap event
            if len(log['topics']) >= 3 and log['topics'][0].hex() == Web3.keccak(text="Swap(address,uint256,uint256,>
                ev = w3.codec.decode_event(pool_abi[0], log["data"], log["topics"])

                # Determine token addresses if not provided
                if not token0 or not token1:
                    # Try to determine from contract address
                    pool_address = log['address']
                    # This would need implementation specific to the pool

                # Get token info
                token0_info = get_token(token0) if token0 else {"decimals": 18, "symbol": "?"}
                token1_info = get_token(token1) if token1 else {"decimals": 18, "symbol": "?"}

                # Calculate amounts with proper decimals
                amount0_in = Decimal(ev["amount0In"]) / Decimal(10 ** token0_info["decimals"])
                amount1_in = Decimal(ev["amount1In"]) / Decimal(10 ** token1_info["decimals"])
                amount0_out = Decimal(ev["amount0Out"]) / Decimal(10 ** token0_info["decimals"])
                amount1_out = Decimal(ev["amount1Out"]) / Decimal(10 ** token1_info["decimals"])

                # Determine direction
                if amount0_in > 0:
                    amt_in, amt_out = amount0_in, amount1_out
                    token_in, token_out = token0_info["symbol"], token1_info["symbol"]
                else:
                    amt_in, amt_out = amount1_in, amount0_out
                    token_in, token_out = token1_info["symbol"], token0_info["symbol"]

                parsed.append((amt_in, amt_out, token_in, token_out))
        except Exception as e:
            logger.debug(f"Failed to parse V2 swap: {e}")

    return parsed

def parse_v3_swaps(receipt, path=None):
    """Parse Uniswap V3 swap events from transaction receipt"""
    v3swap = {
        "anonymous": False, "inputs": [
            {"indexed": True, "name": "sender", "type": "address"},
            {"indexed": True, "name": "recipient", "type": "address"},
            {"indexed": False, "name": "amount0", "type": "int256"},
            {"indexed": False, "name": "amount1", "type": "int256"},
            {"indexed": False, "name": "sqrtPriceX96", "type": "uint160"},
            {"indexed": False, "name": "liquidity", "type": "uint128"},
            {"indexed": False, "name": "tick", "type": "int24"},
        ], "name": "Swap", "type": "event"
    }

    parsed = []
    token0, token1 = None, None

    if path and len(path) >= 2:
        token0, token1 = path[0], path[-1]

    for log in receipt.logs:
        try:
            # Match log to Swap event
            if len(log['topics']) >= 3 and log['topics'][0].hex() == Web3.keccak(text="Swap(address,address,int256,i>
                ev = w3.codec.decode_event(v3swap, log["data"], log["topics"])

                # Determine token addresses if not provided
                if not token0 or not token1:
                    pool_address = log['address']
                    # Implementation specific to V3 pools would be needed

                # Get token info
                token0_info = get_token(token0) if token0 else {"decimals": 18, "symbol": "?"}
                token1_info = get_token(token1) if token1 else {"decimals": 18, "symbol": "?"}

                # Calculate amounts with proper decimals
                am0, am1 = int(ev["amount0"]), int(ev["amount1"])

                # In V3, negative amount means output
                if am0 < 0 and am1 > 0:
                    amt_in = Decimal(am1) / Decimal(10 ** token1_info["decimals"])
                    amt_out = Decimal(abs(am0)) / Decimal(10 ** token0_info["decimals"])
                    token_in, token_out = token1_info["symbol"], token0_info["symbol"]
                elif am1 < 0 and am0 > 0:
                    amt_in = Decimal(am0) / Decimal(10 ** token0_info["decimals"])
                    amt_out = Decimal(abs(am1)) / Decimal(10 ** token1_info["decimals"])
                    token_in, token_out = token0_info["symbol"], token1_info["symbol"]
                else:
                    continue  # Skip if can't determine direction

                parsed.append((amt_in, amt_out, token_in, token_out))
        except Exception as e:
            logger.debug(f"Failed to parse V3 swap: {e}")

    return parsed

# ------------------ TRADE ANALYSIS ------------------
def calculate_price_impact(amt_in, amt_out, expected_price=None):
    """Calculate price impact of a trade"""
    if expected_price is None:
        # Without market price, we can't calculate real impact
        return Decimal('0')

    # Simple price impact calculation
    execution_price = amt_out / amt_in
    impact = (expected_price - execution_price) / expected_price
    return impact

def simulate_trade(router, path, amount_in, slippage=Decimal('0.01')):
    """Simulate a trade to check expected output and price impact"""
    try:
        if router.lower() == UNISWAP_V2.lower():
            # V2 quote
            amounts = uni_v2.functions.getAmountsOut(
                int(amount_in),
                path
            ).call()
            expected_out = Decimal(str(amounts[-1]))

            # Calculate min amount out with slippage
            min_out = expected_out * (1 - slippage)

            # Estimate gas
            gas_estimate = 200000  # Default estimate

            return {
                "expected_out": expected_out,
                "min_out": min_out,
                "gas_estimate": gas_estimate
            }

        elif router.lower() == UNISWAP_V3.lower():
            # V3 is more complex, would need to specify fee tier
            # This is a simplified example
            fee = 3000  # Default fee tier (0.3%)

            # For V3, we'd use quoter contract
            # For simplicity, using a placeholder calculation
            expected_out = amount_in * Decimal('0.98')  # Assume 2% slippage as placeholder
            min_out = expected_out * (1 - slippage)
            gas_estimate = 250000  # Default estimate

            return {
                "expected_out": expected_out,
                "min_out": min_out,
                "gas_estimate": gas_estimate,
                "fee": fee
            }

        return None
    except Exception as e:
        logger.error(f"Simulation error: {e}")
        return None

def is_profitable_opportunity(simulation_result, gas_price):
    """Determine if a trade is profitable after gas costs"""
    if not simulation_result:
        return False

    expected_out = simulation_result["expected_out"]
    gas_estimate = simulation_result["gas_estimate"]

    # Calculate gas cost in ETH
    gas_cost_eth = Decimal(str(gas_estimate)) * Decimal(str(gas_price)) / Decimal(10**18)

    # Convert to token terms (simplified)
    # In a real implementation, you'd need to know the ETH price of the token
    gas_cost_token = gas_cost_eth  # Simplified

    # Calculate expected profit
    profit = expected_out - gas_cost_token

    # Check if profit exceeds minimum threshold
    return profit > MIN_PROFIT_THRESHOLD

# ------------------ TRANSACTION SENDING ------------------

import threading, time
from web3.exceptions import TransactionNotFound

class TxManager:
    def __init__(self, w3, key_manager, wallet_addr):
        self.w3 = w3
        self.key_manager = key_manager  # <- store manager, not privkey
        self.wallet_addr = wallet_addr
        self.nonce_lock = threading.Lock()

    def send(self, tx_dict, wait_for_receipt=True):
        with self.nonce_lock:
            tx_dict['nonce'] = self.w3.eth.get_transaction_count(self.wallet_addr)
            tx_dict['gasPrice'] = int(self.w3.eth.gas_price * GAS_BOOST)

            if 'gas' not in tx_dict:
                try:
                    gas_est = self.w3.eth.estimate_gas(tx_dict)
                    tx_dict['gas'] = int(gas_est * 1.2)
                except Exception as e:
                    logger.warning(f"Gas estimation fail: {e}")
                    tx_dict['gas'] = 500000

            # 🔑 Decrypt only now
            priv_key = self.key_manager()
            signed = self.w3.eth.account.sign_transaction(tx_dict, priv_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)

            logger.info(f"[TX] Sent {tx_hash.hex()} Nonce={tx_dict['nonce']} GasPrice={tx_dict['gasPrice']}")

        if wait_for_receipt:
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            return tx_hash, receipt
        return tx_hash

    def approve(self, token_addr, spender):
        """ERC20 max approval if allowance too low"""
        token = self.w3.eth.contract(address=token_addr, abi=ERC20_ABI)
        allowance = token.functions.allowance(self.wallet_addr, spender).call()
        if allowance < 2**255:
            tx = token.functions.approve(spender, 2**256 - 1).build_transaction({
                'from': self.wallet_addr
            })
            return self.send(tx)
        return None

    def execute_swap_v2(self, token_in, token_out, amount_in, slippage_bps=50):
        """Uniswap V2 style swap (token->token, token->ETH, ETH->token)."""
        path = [token_in['address'], token_out['address']]
        raw_in = int(amount_in * (10 ** token_in['decimals']))
        deadline = int(time.time()) + 600

        # Ensure approval if not ETH
        if token_in['symbol'] != "ETH":
            self.approve(token_in['address'], UNISWAP_V2)

        # Build transaction
        tx = uni_v2.functions.swapExactTokensForTokens(
            raw_in,
            0,  # slippage handling can be layered later
            path,
            self.wallet_addr,
            deadline
        ).build_transaction({'from': self.wallet_addr})
        return self.send(tx)

    def execute_swap_v3(self, token_in, token_out, amount_in, slippage_bps=50):
        """Uniswap V3 swap using exactInputSingle."""
        fee = 3000  # default 0.3% tier
        raw_in = int(amount_in * (10 ** token_in['decimals']))
        deadline = int(time.time()) + 600

        # Ensure approval if not ETH
        if token_in['symbol'] != "ETH":
            self.approve(token_in['address'], UNISWAP_V3)

        params = {
            'tokenIn': token_in['address'],
            'tokenOut': token_out['address'],
            'fee': fee,
            'recipient': self.wallet_addr,
            'deadline': deadline,
            'amountIn': raw_in,
            'amountOutMinimum': 0,   # add slippage calc if needed
            'sqrtPriceLimitX96': 0
        }

        tx = uni_v3.functions.exactInputSingle(params).build_transaction({
            'from': self.wallet_addr,
            'value': raw_in if token_in['symbol'] == "ETH" else 0
        })
        return self.send(tx)


# ---- global init ----
txmgr = TxManager(w3, secure_key_manager, WALLET_ADDR)


# ------------------ MEMPOOL MONITORING ------------------

def decode_input(input_data):
    """
    Decode tx input against Uniswap V2 and V3 ABIs.
    Returns a triple:
        fn_name (string), fn (ABI function object), params (dict)
    If decoding fails → (None, None, None).
    """
    try:
        if not input_data.startswith("0x"):
            return None, None, None

        try:
            fn, params = uni_v2.decode_function_input(input_data)
            return fn.fn_name, fn, params
        except Exception:
            try:
                fn, params = uni_v3.decode_function_input(input_data)
                return fn.fn_name, fn, params
            except Exception:
                return None, None, None

    except Exception as e:
        logger.debug(f"[Decode] Input decode failed: {e}")
        return None, None, None


def parse_swap(tx):
    """
    Parse whale swap tx → dict with:
        from, to, fn_name, token_in/out, amount_in, amount_out_min
    Tokens are resolved & scaled. Logs readable.
    """
    try:
        fn_name, fn, params = decode_input(tx["input"])
        if not fn_name or not params:
            return None

        # Extract input/output token addresses
        token_in_addr  = params.get("tokenIn") \
                         or (params.get("path")[0] if params.get("path") else None)
        token_out_addr = params.get("tokenOut") \
                         or (params.get("path")[-1] if params.get("path") else None)

        # Amounts
        amount_in = params.get("amountIn") \
                    or params.get("amountInExact") \
                    or params.get("amountInMax") \
                    or params.get("amount0In") \
                    or 0

        amount_out_min = params.get("amountOutMinimum") \
                         or params.get("amountOutMin") \
                         or 0

        if not token_in_addr or not token_out_addr:
            logger.debug("[Parse] Missing token addresses")
            return None

        # Resolve metadata from registry
        token_in  = get_token(token_in_addr)
        token_out = get_token(token_out_addr)

        # Scale raw values into human-readable floats
        scaled_in  = format_amount(amount_in, token_in["decimals"])
        scaled_out = format_amount(amount_out_min, token_out["decimals"])

        # Log decoded swap
        logger.info(
            f"[WhaleSwap] fn={fn_name} | Router={tx['to']} | "
            f"{token_in['symbol']} → {token_out['symbol']} | "
            f"In={scaled_in:.4f} | MinOut={scaled_out:.4f} | "
            f"from {tx['from']}"
        )

        return {
            "from": tx["from"],
            "to": (tx["to"] or "").lower(),
            "fn_name": fn_name,
            "token_in": token_in,
            "token_out": token_out,
            "amount_in": scaled_in,
            "amount_out_min": scaled_out,
            "raw": tx
        }

    except Exception as e:
        logger.debug(f"[Parse] Swap parse error: {e}")
        return None


def handle_whale_trade(parsed):
    """
    Allocate + mirror whale trade.
    Router type + fn_name are passed into decide_allocation.
    """

    # Cull bad whales
    if not should_follow(parsed["from"]):
        logger.info(f"[CULL] Dropped whale {parsed['from']} (bad performance)")
        return

    try:
        # Allocation now aware of fn + router
        alloc_size = decide_allocation(
            token_in=parsed["token_in"],
            token_out=parsed["token_out"],
            amount_in=parsed["amount_in"],
            fn_name=parsed["fn_name"],
            router=parsed["to"]
        )

        if alloc_size <= 0:
            logger.info(
                f"[ALLOC] Skipped {parsed['token_out']['symbol']} | "
                f"fn={parsed['fn_name']} | size=0"
            )
            return

        # Route by router address
        tx_hash = None
        if parsed["to"] == UNISWAP_V2.lower():
            tx_hash = txmgr.execute_swap_v2(
                parsed["token_in"], parsed["token_out"], alloc_size
            )
        elif parsed["to"] == UNISWAP_V3.lower():
            tx_hash = txmgr.execute_swap_v3(
                parsed["token_in"], parsed["token_out"], alloc_size
            )
        else:
            logger.debug(f"[EXECUTE] Unsupported router: {parsed['to']}")
            return

        logger.info(
            f"[EXECUTE] Mirrored fn={parsed['fn_name']} on "
            f"{'V2' if parsed['to']==UNISWAP_V2.lower() else 'V3'} | "
            f"{parsed['token_in']['symbol']}→{parsed['token_out']['symbol']} "
            f"| size={alloc_size} | tx={tx_hash.hex()}"
        )

    except Exception as e:
        logger.error(f"[TradeHandler] Execution failure: {e}")


def process_whale_tx(tx):
    """
    Process a single pending tx if it's from tracked whale
    and router matches V2 or V3.
    """
    try:
        to_addr = (tx["to"] or "").lower()
        if to_addr not in [UNISWAP_V2.lower(), UNISWAP_V3.lower()]:
            return

        parsed = parse_swap(tx)
        if parsed:
            handle_whale_trade(parsed)

    except Exception as e:
        logger.error(f"[Mempool] Whale tx process error: {e}")


def watch_mempool():
    """
    Subscribe to mempool pending txs.
    Filters for tracked whales → process tx.
    In --dry-run-mempoolhack mode, simulate by scanning latest blocks.
    """
    if getattr(args, "dry_run_mempoolhack", False):
        logger.info("[MempoolHack] Using confirmed blocks instead of pending mempool…")
        last_block = w3.eth.block_number
        while True:
            try:
                new_block = w3.eth.block_number
                if new_block > last_block:
                    for i in range(last_block + 1, new_block + 1):
                        block = w3.eth.get_block(i, full_transactions=True)
                        for tx in block.transactions:
                            try:
                                if tx["from"].lower() in [w.lower() for w in config["tracked_whales"]]:
                                    process_whale_tx(tx)
                            except Exception as e:
                                logger.debug(f"[MempoolHack] Block tx parse fail: {e}")
                                continue
                    last_block = new_block
                time.sleep(2)
            except Exception as e:
                logger.error(f"[MempoolHack] Fatal block-backfill error: {e}")
                time.sleep(3)

    else:
        logger.info("[Mempool] Watching pending transactions…")
        pending_filter = w3.eth.filter("pending")

        while True:
            try:
                for tx_hash in pending_filter.get_new_entries():
                    try:
                        tx = w3.eth.get_transaction(tx_hash)

                        # Check if whale is tracked
                        if tx["from"].lower() in [w.lower() for w in config["tracked_whales"]]:
                            process_whale_tx(tx)

                    except TransactionNotFound:
                        # tx fell out of pool before processing
                        continue
                    except Exception as e:
                        logger.debug(f"[Mempool] Tx fetch fail: {e}")
                        continue

                time.sleep(0.5)

            except Exception as e:
                logger.error(f"[Mempool] Fatal watcher error: {e}")
                time.sleep(3)


# ------------------ ALLOCATION / STRATEGY ------------------

def decide_allocation(token_in, token_out, amount_in, fn_name, router):
    """
    Decide how much to allocate when mirroring a whale trade.

    Args:
        token_in  (dict): {symbol, address, decimals}
        token_out (dict): {symbol, address, decimals}
        amount_in (float): Whale's input amount (human-readable scale)
        fn_name   (str):   Function name (e.g. swapExactTokensForTokens, exactInputSingle)
        router    (str):   Router address (normalized lowercase)

    Returns:
        float: size of YOUR mirror trade (0 => skip)
    """

    # ---- EXAMPLE STRATEGY ----

    # Skip dust or tiny trades
    if amount_in < 100:
        return 0

    # Scale by whale size, capped to your risk tolerance
    max_alloc = 5000      # never spend more than this (your currency units)
    base_alloc = min(amount_in * 0.1, max_alloc)   # default 10%

    # Bias decisions based on router
    if router == UNISWAP_V2.lower():
        # maybe trust V2 less → cut in half
        base_alloc *= 0.5
    elif router == UNISWAP_V3.lower():
        # prefer V3 exactInputSingle
        if "exactInputSingle" in fn_name:
            base_alloc *= 1.5
        elif fn_name.startswith("swapExactETHForTokens"):
            # maybe skip ETH→token plays
            return 0

    return base_alloc



# ------------------ DASHBOARD ------------------
app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Allocator AI - {{ mode }} Mode</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
        }
        .positive { color: #28a745; }
        .negative { color: #dc3545; }
        .neutral { color: #007bff; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            background-color: #fff;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            border-radius: 5px;
            overflow: hidden;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #007bff;
            color: white;
            position: sticky;
            top: 0;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .whale-risk-high { background-color: rgba(220, 53, 69, 0.1); }
        .whale-risk-medium { background-color: rgba(255, 193, 7, 0.1); }
        .whale-risk-profitable { background-color: rgba(40, 167, 69, 0.1); }
        .mode {
            font-weight: bold;
            padding: 5px 10px;
            border-radius: 3px;
        }
        .mode-test { background-color: #ffc107; color: #000; }
        .mode-dry { background-color: #17a2b8; color: #fff; }
        .mode-live { background-color: #28a745; color: #fff; }
        .trades {
            margin-top: 20px;
        }
        }
        @media (max-width: 768px) {
            table {
                display: block;
                overflow-x: auto;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Allocator AI</h1>
        <span class="mode mode-{{ mode.lower() }}">{{ mode }} MODE</span>
    </div>

    <div class="stats">
        <div class="stat-card">
            <h3>Total PnL</h3>
            <div class="stat-value {{ 'positive' if total_pnl > 0 else 'negative' if total_pnl < 0 else 'neutral' }}>
                {{ '%.4f' | format(total_pnl) }} ETH
            </div>
        </div>
        <div class="stat-card">
            <h3>Active Capital</h3>
            <div class="stat-value neutral">{{ '%.4f' | format(capital) }} ETH</div>
        </div>
        <div class="stat-card">
            <h3>Tracked Whales</h3>
            <div class="stat-value neutral">{{ whale_count }}</div>
        </div>
        <div class="stat-card">
            <h3>Total Trades</h3>
            <div class="stat-value neutral">{{ trade_count }}</div>
        </div>
    </div>

    <h2>Whale Performance</h2>
    <table>
                                                                                                                    >

        <tr>
            <th>Whale Address</th>
            <th>Cumulative PnL</th>
            <th>Risk Multiplier</th>
            <th>Allocation Size</th>
            <th>Trade Count</th>
            <th>Score</th>
            <th>Winrate</th>
        </tr>
        {% for w in whales %}
        <tr class="{{ 'whale-risk-profitable' if w.pnl > 0 else 'whale-risk-high' if w.risk < 0.5 else 'whale-risk-m>
            <td>{{ w.address }}</td>
            <td class="{{ 'positive' if w.pnl > 0 else 'negative' }}">{{ '%.4f' | format(w.pnl) }}</td>
            <td>{{ '%.2f' | format(w.risk) }}x</td>
            <td>{{ '%.4f' | format(w.allocation) }} ETH</td>
            <td>{{ w.count }}</td>
            <td>{{ '%.4f' | format(WHALE_SCORES.get(w.address, {}).get('score', 0)) }}</td>
            <td>{{ '%.0f' | format(WHALE_SCORES.get(w.address, {}).get('winrate', 0) * 100) }}%</td>
        </tr>
        {% endfor %}
    </table>
    <h2>Currently Followed Whales</h2>
    <table>
      <tr><th>Whale Address</th><th>Status</th></tr>
      {% for w in following %}
        <tr><td>{{ w }}</{{ w }}</td><td>Following</td></tr>
      {% endfor %}
    <table>

    <h2>Recent Trades</h2>
    <table class="trades">
        <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Direction</th>
            <th>Amount In</th>
            <th>Amount Out</th>
            <th>PnL</th>
            <th>Mode</th>
        </tr>
        {% for t in trades %}
        <tr>
            <td>{{ t.timestamp }}</td>
            <td>{{ t.actor }}</td>
            <td>{{ t.token_in }} → {{ t.token_out }}</td>
            <td>{{ '%.4f' | format(t.amount_in) }}</td>
            <td>{{ '%.4f' | format(t.amount_out) }}</td>
            <td class="{{ 'positive' if t.pnl > 0 else 'negative' if t.pnl < 0 else 'neutral' }}">
                {{ '%.4f' | format(t.pnl) }}
            </td>
            <td>{{ t.mode }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route("/")
def index():
    """Render the dashboard"""
    # Calculate stats
    total_pnl = sum(my_pnl.values())
    trade_count = len([t for t in trade_history if t["actor"] == "allocator"])

    # Prepare whale data
    whale_data = []
    for whale, pnl in my_pnl.items():
        whale_trades = [t for t in trade_history if t["whale"] == whale]
        whale_data.append({
            "address": whale,
            "pnl": float(pnl),
            "risk": float(risk_mult[whale]),
            "allocation": float(capital * BASE_RISK * risk_mult[whale]),
            "count": len(whale_trades)
        })

    # Sort whales by PnL
    whale_data.sort(key=lambda x: x["pnl"], reverse=True)

    # Get recent trades (most recent first)
    recent_trades = sorted(trade_history, key=lambda x: x["timestamp"], reverse=True)[:20]

    mode = (
    "TEST" if TEST_MODE
    else "DRY" if DRY_RUN
    else "DRY_MEMPOOLHACK" if DRY_RUN_MEMPOOLHACK
    else "LIVE"
)


    return render_template_string(
        TEMPLATE,
        whales=whale_data,
        trades=recent_trades,
        total_pnl=float(total_pnl),
        capital=float(capital),
        whale_count=len(tracked_whales),
        trade_count=trade_count,
        mode=mode,
        following=list(tracked_whales)
    )

@app.route("/api/stats")
def api_stats():
    """API endpoint for stats"""
    total_pnl = sum(my_pnl.values())

    return {
        "total_pnl": float(total_pnl),
        "capital": float(capital),
        "whale_count": len(tracked_whales),
        "trade_count": len([t for t in trade_history if t["actor"] == "allocator"]),
        "mode": "TEST" if TEST_MODE else ("DRY" if DRY_RUN else ("DRY_MEMPOOLHACK" if DRY_RUN_MEMPOOLHACK else "LIVE>
    }

@app.route("/api/following")
def api_following():
    return {"following": list(tracked_whales)}


def run_dashboard():
    """Run the dashboard server"""
    try:
        app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
# ------------------ DISCOVER WHALES -------

def discover_whales(blocks_back=2000, min_trades=3, min_pnl_threshold=1):
    """
    Crawl recent blocks, score active wallets, auto-add top whales into tracked_whales.
    """
    logger.info(f"[Discovery] Backfilling last {blocks_back} blocks for alpha whales...")
    start_block = max(0, w3.eth.block_number - blocks_back)
    candidate_stats = defaultdict(lambda: {"profit": Decimal(0), "trades": 0})

    for i in range(start_block, w3.eth.block_number + 1):
        try:
            block = w3.eth.get_block(i, full_transactions=True)
            for tx in block.transactions:
                # Only trades through UniV2/V3 routers
                if (tx.to or "").lower() not in [UNISWAP_V2.lower(), UNISWAP_V3.lower()]:
                    continue
               actor = tx["from"].lower()
                candidate_stats[actor]["trades"] += 1
                # crude proxy pnl = in-out for token amounts you parse
                # here just counting notional size until real pnl calc
                candidate_stats[actor]["profit"] += Decimal(tx.value) / (10**18)

        except Exception as e:
            logger.debug(f"[Discovery] block {i}{i} skipped: {e}")

    # filter to whales
    new_whales = []
    for addr, stats in candidate_stats.items():
        if stats["trades"] >= min_trades and stats["profit"] >= min_pnl_threshold:
            new_whales.append(addr)

    logger.info(f"[Discovery] Found {len(new_whales)} whales worth tracking.")

    # merge into your runtime set
    for w in new_whales:
        if w not in tracked_whales:
            tracked_whales.add(w)
            logger.info(f"[Discovery] Added whale {w}")




# ------------------ MAIN ------------------
def main():
    """Main execution function"""
    logger.info(f"Starting Allocator AI in {'TEST' if TEST_MODE else ('DRY_RUN' if DRY_RUN else ('DRY_RUN_MEMPOOLHAC>

    # Start dashboard in a separate thread
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()

    # --- seed tracked whales from config so UI isn't empty at start ---
    for addr in config.get("tracked_whales", []):
        tracked_whales.add(Web3.to_checksum_address(addr))
    if tracked_whales:
        logger.info(f"[MAIN] Seeded with {len(tracked_whales)} whales from config")

    # --- background refresh of discovery so whales accumulate over time ---
    def periodic_discover(interval=600):
        while True:
            try:
                discover_whales(blocks_back=2000, min_trades=2, min_pnl_threshold=0.5)
                logger.info(f"[PeriodicDiscovery] now tracking {len(tracked_whales)} whales")
            except Exception as e:
                logger.warning(f"[PeriodicDiscovery] error: {e}")
            time.sleep(interval)
    threading.Thread(target=periodic_discover, daemon=True).start()

    try:
        # Initial discover at startup (more strict if you like)
        discover_whales(blocks_back=10000, min_trades=5, min_pnl_threshold=2)
        logger.info(f"[MAIN] Tracking {len(tracked_whales)} whales after discovery")
        # Start mempool monitoring
        watch_mempool()
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        # Cleanup
        logger.info("Allocator AI shutdown complete")

if __name__ == "__main__":
    main()
