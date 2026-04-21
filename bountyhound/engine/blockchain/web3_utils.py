"""
Web3 Blockchain Utilities
Utilities for interacting with Ethereum and EVM-compatible blockchains
"""

from typing import List, Dict, Optional, Any
from colorama import Fore, Style
import json

try:
    from web3 import Web3
    from web3.middleware import geth_poa_middleware
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    Web3 = None
    geth_poa_middleware = None


class Web3Utils:
    """
    Core Web3 utilities for blockchain interaction
    """

    def __init__(self, provider_url: str = 'http://localhost:8545'):
        """
        Initialize Web3 connection

        Args:
            provider_url: RPC endpoint URL
        """
        if not WEB3_AVAILABLE:
            raise ImportError("web3.py is required for blockchain utilities. Install: pip install web3")

        self.provider_url = provider_url

        # Initialize provider based on URL
        if provider_url.startswith('ws'):
            self.w3 = Web3(Web3.WebsocketProvider(provider_url))
        else:
            self.w3 = Web3(Web3.HTTPProvider(provider_url))

        # Add PoA middleware for networks like BSC, Polygon
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    def is_connected(self) -> bool:
        """Check if connected to blockchain"""
        return self.w3.is_connected()

    def get_balance(self, address: str) -> float:
        """
        Get account balance in Ether

        Args:
            address: Ethereum address

        Returns:
            Balance in Ether
        """
        balance_wei = self.w3.eth.get_balance(address)
        return self.w3.from_wei(balance_wei, 'ether')

    def get_transaction_count(self, address: str) -> int:
        """
        Get transaction count (nonce) for address

        Args:
            address: Ethereum address

        Returns:
            Transaction count
        """
        return self.w3.eth.get_transaction_count(address)

    def create_account(self) -> Dict[str, str]:
        """
        Create new Ethereum account

        Returns:
            Dictionary with address and private key
        """
        account = self.w3.eth.account.create()
        return {
            'address': account.address,
            'private_key': account.key.hex()
        }

    def get_block_number(self) -> int:
        """Get current block number"""
        return self.w3.eth.block_number

    def get_block_info(self, block_number: int) -> Dict:
        """
        Get block information

        Args:
            block_number: Block number to query

        Returns:
            Block information
        """
        return dict(self.w3.eth.get_block(block_number))

    def send_transaction(self, from_address: str, to_address: str,
                        value: int, private_key: str,
                        gas: int = 21000, gas_price: Optional[int] = None) -> str:
        """
        Send transaction

        Args:
            from_address: Sender address
            to_address: Recipient address
            value: Amount in Wei
            private_key: Sender's private key
            gas: Gas limit
            gas_price: Gas price in Wei (optional)

        Returns:
            Transaction hash
        """
        nonce = self.w3.eth.get_transaction_count(from_address)

        tx = {
            'nonce': nonce,
            'to': to_address,
            'value': value,
            'gas': gas,
            'gasPrice': gas_price or self.w3.eth.gas_price
        }

        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

        return tx_hash.hex()

    def call_contract_function(self, contract_address: str, abi: List[Dict],
                              function_name: str, *args) -> Any:
        """
        Call contract function (read-only)

        Args:
            contract_address: Contract address
            abi: Contract ABI
            function_name: Function to call
            *args: Function arguments

        Returns:
            Function return value
        """
        contract = self.w3.eth.contract(address=contract_address, abi=abi)
        function = getattr(contract.functions, function_name)
        return function(*args).call()

    def execute_contract_function(self, contract_address: str, abi: List[Dict],
                                 function_name: str, from_address: str,
                                 private_key: str, *args,
                                 gas: int = 200000) -> str:
        """
        Execute contract function (write)

        Args:
            contract_address: Contract address
            abi: Contract ABI
            function_name: Function to execute
            from_address: Caller address
            private_key: Caller's private key
            *args: Function arguments
            gas: Gas limit

        Returns:
            Transaction hash
        """
        contract = self.w3.eth.contract(address=contract_address, abi=abi)
        function = getattr(contract.functions, function_name)

        nonce = self.w3.eth.get_transaction_count(from_address)

        tx = function(*args).build_transaction({
            'from': from_address,
            'nonce': nonce,
            'gas': gas,
            'gasPrice': self.w3.eth.gas_price
        })

        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

        return tx_hash.hex()

    def to_checksum_address(self, address: str) -> str:
        """Convert address to checksum format"""
        return self.w3.to_checksum_address(address)

    def is_address(self, address: str) -> bool:
        """Check if string is valid address"""
        return self.w3.is_address(address)

    def wei_to_ether(self, wei: int) -> float:
        """Convert Wei to Ether"""
        return self.w3.from_wei(wei, 'ether')

    def ether_to_wei(self, ether: float) -> int:
        """Convert Ether to Wei"""
        return self.w3.to_wei(ether, 'ether')


class ContractDeployer:
    """
    Smart contract deployment utilities
    """

    def __init__(self, provider_url: str = 'http://localhost:8545'):
        """
        Initialize deployer

        Args:
            provider_url: RPC endpoint URL
        """
        self.utils = Web3Utils(provider_url)
        self.w3 = self.utils.w3

    def deploy(self, bytecode: str, abi: List[Dict],
              from_address: str, private_key: str,
              *constructor_args, gas: int = 3000000) -> Dict:
        """
        Deploy smart contract

        Args:
            bytecode: Contract bytecode
            abi: Contract ABI
            from_address: Deployer address
            private_key: Deployer's private key
            *constructor_args: Constructor arguments
            gas: Gas limit

        Returns:
            Deployment result with contract address
        """
        try:
            contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)

            nonce = self.w3.eth.get_transaction_count(from_address)

            tx = contract.constructor(*constructor_args).build_transaction({
                'from': from_address,
                'nonce': nonce,
                'gas': gas,
                'gasPrice': self.w3.eth.gas_price
            })

            signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'status': 'success' if receipt['status'] == 1 else 'failed',
                'contract_address': receipt.get('contractAddress'),
                'transaction_hash': tx_hash.hex(),
                'gas_used': receipt['gasUsed']
            }

        except Exception as e:
            return {
                'status': 'failed',
                'error': str(e)
            }

    def estimate_deployment_gas(self, bytecode: str, abi: List[Dict],
                               *constructor_args) -> int:
        """
        Estimate gas for deployment

        Args:
            bytecode: Contract bytecode
            abi: Contract ABI
            *constructor_args: Constructor arguments

        Returns:
            Estimated gas
        """
        contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        return contract.constructor(*constructor_args).estimate_gas()


class TransactionAnalyzer:
    """
    Transaction analysis utilities
    """

    def __init__(self, provider_url: str = 'http://localhost:8545'):
        """
        Initialize analyzer

        Args:
            provider_url: RPC endpoint URL
        """
        self.utils = Web3Utils(provider_url)
        self.w3 = self.utils.w3

    def analyze(self, tx_hash: str) -> Dict:
        """
        Analyze transaction

        Args:
            tx_hash: Transaction hash

        Returns:
            Transaction analysis
        """
        tx = self.w3.eth.get_transaction(tx_hash)
        receipt = self.w3.eth.get_transaction_receipt(tx_hash)

        return {
            'hash': tx_hash,
            'status': 'success' if receipt['status'] == 1 else 'failed',
            'from': tx['from'],
            'to': tx.get('to'),
            'value': tx['value'],
            'gas': tx['gas'],
            'gas_price': tx['gasPrice'],
            'gas_used': receipt['gasUsed'],
            'nonce': tx['nonce'],
            'block_number': receipt['blockNumber'],
            'logs': receipt.get('logs', [])
        }

    def decode_input_data(self, input_data: str, abi: List[Dict]) -> Dict:
        """
        Decode transaction input data

        Args:
            input_data: Transaction input data
            abi: Contract ABI

        Returns:
            Decoded function call
        """
        try:
            contract = self.w3.eth.contract(abi=abi)
            func_obj, func_params = contract.decode_function_input(input_data)

            return {
                'function': func_obj.function_identifier,
                'parameters': func_params
            }
        except Exception as e:
            return {
                'error': str(e),
                'raw_input': input_data
            }

    def calculate_transaction_cost(self, tx_hash: str) -> float:
        """
        Calculate total transaction cost in Ether

        Args:
            tx_hash: Transaction hash

        Returns:
            Cost in Ether
        """
        receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        tx = self.w3.eth.get_transaction(tx_hash)

        gas_used = receipt['gasUsed']
        gas_price = tx['gasPrice']

        cost_wei = gas_used * gas_price
        return self.w3.from_wei(cost_wei, 'ether')


class EventMonitor:
    """
    Smart contract event monitoring utilities
    """

    def __init__(self, provider_url: str = 'http://localhost:8545'):
        """
        Initialize event monitor

        Args:
            provider_url: RPC endpoint URL
        """
        self.utils = Web3Utils(provider_url)
        self.w3 = self.utils.w3

    def monitor_events(self, contract_address: str, abi: List[Dict],
                      event_name: str, from_block: int = 0,
                      to_block: str = 'latest') -> List[Dict]:
        """
        Monitor contract events

        Args:
            contract_address: Contract address
            abi: Contract ABI
            event_name: Event name to monitor
            from_block: Starting block
            to_block: Ending block

        Returns:
            List of events
        """
        contract = self.w3.eth.contract(address=contract_address, abi=abi)
        event = getattr(contract.events, event_name)

        event_filter = event.create_filter(fromBlock=from_block, toBlock=to_block)
        return event_filter.get_all_entries()

    def get_events_from_logs(self, logs: List[Dict], abi: List[Dict],
                            contract_address: str) -> List[Dict]:
        """
        Extract events from transaction logs

        Args:
            logs: Transaction logs
            abi: Contract ABI
            contract_address: Contract address

        Returns:
            Decoded events
        """
        contract = self.w3.eth.contract(address=contract_address, abi=abi)
        events = []

        for log in logs:
            try:
                # Try to decode each event
                for event in abi:
                    if event.get('type') == 'event':
                        try:
                            decoded = getattr(contract.events, event['name'])().process_log(log)
                            events.append(decoded)
                            break
                        except:
                            continue
            except Exception:
                continue

        return events

    def decode_event_log(self, log: Dict, abi: List[Dict],
                        event_name: str, contract_address: str) -> Dict:
        """
        Decode specific event log

        Args:
            log: Event log
            abi: Contract ABI
            event_name: Event name
            contract_address: Contract address

        Returns:
            Decoded event
        """
        contract = self.w3.eth.contract(address=contract_address, abi=abi)
        event = getattr(contract.events, event_name)

        try:
            return event().process_log(log)
        except Exception as e:
            return {'error': str(e)}


def main():
    """CLI interface for testing"""
    import sys

    print(f"{Fore.CYAN}=== Web3 Utilities ==={Style.RESET_ALL}")

    # Example usage
    utils = Web3Utils('http://localhost:8545')

    if utils.is_connected():
        print(f"{Fore.GREEN}[+] Connected to blockchain{Style.RESET_ALL}")
        print(f"Current block: {utils.get_block_number()}")
    else:
        print(f"{Fore.RED}[-] Not connected{Style.RESET_ALL}")
        print("Start a local blockchain (ganache-cli, hardhat, etc.)")


if __name__ == "__main__":
    main()
