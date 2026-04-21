"""
Tests for Web3 Utilities
Comprehensive testing of Web3 blockchain interaction utilities
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys

# Mock web3 before importing
mock_web3_module = MagicMock()
mock_middleware = MagicMock()
mock_middleware.geth_poa_middleware = MagicMock()

sys.modules['web3'] = mock_web3_module
sys.modules['web3.middleware'] = mock_middleware

# Now we can import - web3_utils will use the mocked modules
import importlib
import engine.blockchain.web3_utils
importlib.reload(engine.blockchain.web3_utils)

from engine.blockchain.web3_utils import (
    Web3Utils,
    ContractDeployer,
    TransactionAnalyzer,
    EventMonitor
)


class TestWeb3UtilsInit:
    """Test Web3Utils initialization"""

    @patch('engine.blockchain.web3_utils.Web3')
    def test_init_with_http_provider(self, mock_web3):
        """Should initialize with HTTP provider"""
        utils = Web3Utils('http://localhost:8545')

        assert utils.provider_url == 'http://localhost:8545'
        mock_web3.HTTPProvider.assert_called_once()

    @patch('engine.blockchain.web3_utils.Web3')
    def test_init_with_https_provider(self, mock_web3):
        """Should initialize with HTTPS provider"""
        utils = Web3Utils('https://mainnet.infura.io/v3/key')

        assert utils.provider_url == 'https://mainnet.infura.io/v3/key'

    @patch('engine.blockchain.web3_utils.Web3')
    def test_init_with_websocket_provider(self, mock_web3):
        """Should initialize with WebSocket provider"""
        utils = Web3Utils('ws://localhost:8546')

        assert utils.provider_url == 'ws://localhost:8546'

    @patch('engine.blockchain.web3_utils.Web3')
    def test_is_connected(self, mock_web3):
        """Should check connection status"""
        mock_w3 = Mock()
        mock_w3.is_connected.return_value = True
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')

        assert utils.is_connected() is True


class TestAccountManagement:
    """Test account management"""

    @patch('engine.blockchain.web3_utils.Web3')
    def test_get_balance(self, mock_web3):
        """Should get account balance"""
        mock_w3 = Mock()
        mock_w3.eth.get_balance.return_value = 1000000000000000000  # 1 ETH in Wei
        mock_w3.from_wei.return_value = 1.0
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')
        balance = utils.get_balance('0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb')

        assert balance == 1.0

    @patch('engine.blockchain.web3_utils.Web3')
    def test_get_transaction_count(self, mock_web3):
        """Should get transaction count (nonce)"""
        mock_w3 = Mock()
        mock_w3.eth.get_transaction_count.return_value = 42
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')
        nonce = utils.get_transaction_count('0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb')

        assert nonce == 42

    @patch('engine.blockchain.web3_utils.Web3')
    def test_create_account(self, mock_web3):
        """Should create new account"""
        mock_w3 = Mock()
        mock_account = Mock()
        mock_account.address = '0xNewAddress'
        mock_account.key = b'private_key'
        mock_w3.eth.account.create.return_value = mock_account
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')
        account = utils.create_account()

        assert 'address' in account
        assert 'private_key' in account


class TestContractDeployer:
    """Test contract deployment"""

    @patch('engine.blockchain.web3_utils.Web3')
    def test_deploy_contract_success(self, mock_web3):
        """Should deploy contract successfully"""
        mock_w3 = Mock()
        mock_w3.eth.account.sign_transaction.return_value = Mock(rawTransaction=b'signed')
        mock_w3.eth.send_raw_transaction.return_value = b'tx_hash'
        mock_w3.eth.wait_for_transaction_receipt.return_value = {
            'contractAddress': '0xContractAddress',
            'status': 1
        }
        mock_web3.return_value = mock_w3

        deployer = ContractDeployer('http://localhost:8545')

        bytecode = '0x608060405234801561001057600080fd5b50'
        abi = [{"inputs": [], "stateMutability": "nonpayable", "type": "constructor"}]

        result = deployer.deploy(bytecode, abi, '0xDeployerAddress', 'private_key')

        assert 'contract_address' in result
        assert result['status'] == 'success'

    @patch('engine.blockchain.web3_utils.Web3')
    def test_deploy_contract_failure(self, mock_web3):
        """Should handle deployment failure"""
        mock_w3 = Mock()
        mock_w3.eth.send_raw_transaction.side_effect = Exception("Deployment failed")
        mock_web3.return_value = mock_w3

        deployer = ContractDeployer('http://localhost:8545')

        bytecode = '0x608060405234801561001057600080fd5b50'
        abi = []

        result = deployer.deploy(bytecode, abi, '0xDeployerAddress', 'private_key')

        assert result['status'] == 'failed'

    @patch('engine.blockchain.web3_utils.Web3')
    def test_estimate_gas(self, mock_web3):
        """Should estimate deployment gas"""
        mock_w3 = Mock()
        mock_contract = Mock()
        mock_contract.constructor().estimate_gas.return_value = 500000
        mock_w3.eth.contract.return_value = mock_contract
        mock_web3.return_value = mock_w3

        deployer = ContractDeployer('http://localhost:8545')

        bytecode = '0x608060405234801561001057600080fd5b50'
        abi = []

        gas = deployer.estimate_deployment_gas(bytecode, abi)

        assert gas == 500000


class TestTransactionAnalyzer:
    """Test transaction analysis"""

    @patch('engine.blockchain.web3_utils.Web3')
    def test_analyze_transaction_success(self, mock_web3):
        """Should analyze transaction successfully"""
        mock_w3 = Mock()
        mock_w3.eth.get_transaction.return_value = {
            'hash': '0xTxHash',
            'from': '0xFrom',
            'to': '0xTo',
            'value': 1000000000000000000,
            'gas': 21000,
            'gasPrice': 20000000000,
            'nonce': 5
        }
        mock_w3.eth.get_transaction_receipt.return_value = {
            'status': 1,
            'gasUsed': 21000,
            'logs': []
        }
        mock_web3.return_value = mock_w3

        analyzer = TransactionAnalyzer('http://localhost:8545')
        result = analyzer.analyze('0xTxHash')

        assert result['status'] == 'success'
        assert result['from'] == '0xFrom'
        assert result['to'] == '0xTo'
        assert 'gas_used' in result

    @patch('engine.blockchain.web3_utils.Web3')
    def test_analyze_failed_transaction(self, mock_web3):
        """Should detect failed transaction"""
        mock_w3 = Mock()
        mock_w3.eth.get_transaction.return_value = {'hash': '0xTxHash'}
        mock_w3.eth.get_transaction_receipt.return_value = {
            'status': 0,  # Failed
            'gasUsed': 21000
        }
        mock_web3.return_value = mock_w3

        analyzer = TransactionAnalyzer('http://localhost:8545')
        result = analyzer.analyze('0xTxHash')

        assert result['status'] == 'failed'

    @patch('engine.blockchain.web3_utils.Web3')
    def test_decode_input_data(self, mock_web3):
        """Should decode transaction input data"""
        mock_w3 = Mock()
        mock_contract = Mock()
        mock_contract.decode_function_input.return_value = (
            Mock(function_identifier='transfer'),
            {'to': '0xRecipient', 'value': 100}
        )
        mock_w3.eth.contract.return_value = mock_contract
        mock_web3.return_value = mock_w3

        analyzer = TransactionAnalyzer('http://localhost:8545')

        abi = [{"name": "transfer", "type": "function"}]
        input_data = '0xa9059cbb...'

        result = analyzer.decode_input_data(input_data, abi)

        assert 'function' in result
        assert 'parameters' in result

    @patch('engine.blockchain.web3_utils.Web3')
    def test_calculate_transaction_cost(self, mock_web3):
        """Should calculate transaction cost"""
        mock_w3 = Mock()
        mock_w3.eth.get_transaction_receipt.return_value = {
            'gasUsed': 21000
        }
        mock_w3.eth.get_transaction.return_value = {
            'gasPrice': 20000000000  # 20 Gwei
        }
        mock_w3.from_wei.return_value = 0.00042  # 21000 * 20 Gwei
        mock_web3.return_value = mock_w3

        analyzer = TransactionAnalyzer('http://localhost:8545')
        cost = analyzer.calculate_transaction_cost('0xTxHash')

        assert cost == 0.00042


class TestEventMonitor:
    """Test event monitoring"""

    @patch('engine.blockchain.web3_utils.Web3')
    def test_get_events_from_logs(self, mock_web3):
        """Should extract events from logs"""
        mock_w3 = Mock()
        mock_contract = Mock()

        # Mock event processing
        mock_contract.events.Transfer().process_log.return_value = {
            'event': 'Transfer',
            'args': {
                'from': '0xFrom',
                'to': '0xTo',
                'value': 100
            }
        }
        mock_w3.eth.contract.return_value = mock_contract
        mock_web3.return_value = mock_w3

        monitor = EventMonitor('http://localhost:8545')

        abi = [{"name": "Transfer", "type": "event"}]
        logs = [{'topics': ['0xddf...'], 'data': '0x...'}]

        events = monitor.get_events_from_logs(logs, abi, '0xContractAddress')

        assert isinstance(events, list)

    @patch('engine.blockchain.web3_utils.Web3')
    def test_monitor_events_in_range(self, mock_web3):
        """Should monitor events in block range"""
        mock_w3 = Mock()
        mock_contract = Mock()
        mock_filter = Mock()
        mock_filter.get_all_entries.return_value = [
            {'event': 'Transfer', 'args': {'value': 100}}
        ]
        mock_contract.events.Transfer.create_filter.return_value = mock_filter
        mock_w3.eth.contract.return_value = mock_contract
        mock_web3.return_value = mock_w3

        monitor = EventMonitor('http://localhost:8545')

        abi = [{"name": "Transfer", "type": "event"}]

        events = monitor.monitor_events(
            '0xContractAddress',
            abi,
            'Transfer',
            from_block=100,
            to_block=200
        )

        assert isinstance(events, list)

    @patch('engine.blockchain.web3_utils.Web3')
    def test_decode_event_log(self, mock_web3):
        """Should decode event log"""
        mock_w3 = Mock()
        mock_contract = Mock()
        mock_contract.events.Transfer().process_log.return_value = {
            'event': 'Transfer',
            'args': {'from': '0xFrom', 'to': '0xTo', 'value': 100}
        }
        mock_w3.eth.contract.return_value = mock_contract
        mock_web3.return_value = mock_w3

        monitor = EventMonitor('http://localhost:8545')

        abi = [{"name": "Transfer", "type": "event"}]
        log = {'topics': ['0xddf...'], 'data': '0x...'}

        decoded = monitor.decode_event_log(log, abi, 'Transfer', '0xContractAddress')

        assert 'event' in decoded or decoded is not None


class TestBlockchainInteraction:
    """Test general blockchain interaction"""

    @patch('engine.blockchain.web3_utils.Web3')
    def test_get_block_number(self, mock_web3):
        """Should get current block number"""
        mock_w3 = Mock()
        mock_w3.eth.block_number = 12345678
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')
        block_num = utils.get_block_number()

        assert block_num == 12345678

    @patch('engine.blockchain.web3_utils.Web3')
    def test_get_block_info(self, mock_web3):
        """Should get block information"""
        mock_w3 = Mock()
        mock_w3.eth.get_block.return_value = {
            'number': 12345678,
            'timestamp': 1234567890,
            'transactions': ['0xTx1', '0xTx2'],
            'gasUsed': 8000000
        }
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')
        block = utils.get_block_info(12345678)

        assert block['number'] == 12345678
        assert 'transactions' in block

    @patch('engine.blockchain.web3_utils.Web3')
    def test_send_transaction(self, mock_web3):
        """Should send transaction"""
        mock_w3 = Mock()
        mock_w3.eth.account.sign_transaction.return_value = Mock(rawTransaction=b'signed')
        mock_w3.eth.send_raw_transaction.return_value = b'tx_hash'
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')

        tx_hash = utils.send_transaction(
            from_address='0xFrom',
            to_address='0xTo',
            value=1000000000000000000,
            private_key='private_key'
        )

        assert tx_hash is not None


class TestContractInteraction:
    """Test smart contract interaction"""

    @patch('engine.blockchain.web3_utils.Web3')
    def test_call_contract_function(self, mock_web3):
        """Should call contract function (read)"""
        mock_w3 = Mock()
        mock_contract = Mock()
        mock_function = Mock()
        mock_function.call.return_value = 42
        mock_contract.functions.balanceOf.return_value = mock_function
        mock_w3.eth.contract.return_value = mock_contract
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')

        abi = [{"name": "balanceOf", "type": "function"}]

        result = utils.call_contract_function(
            '0xContractAddress',
            abi,
            'balanceOf',
            '0xAddress'
        )

        assert result == 42

    @patch('engine.blockchain.web3_utils.Web3')
    def test_execute_contract_function(self, mock_web3):
        """Should execute contract function (write)"""
        mock_w3 = Mock()
        mock_contract = Mock()
        mock_function = Mock()
        mock_function.build_transaction.return_value = {
            'nonce': 5,
            'gas': 100000,
            'gasPrice': 20000000000
        }
        mock_contract.functions.transfer.return_value = mock_function
        mock_w3.eth.contract.return_value = mock_contract
        mock_w3.eth.account.sign_transaction.return_value = Mock(rawTransaction=b'signed')
        mock_w3.eth.send_raw_transaction.return_value = b'tx_hash'
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')

        abi = [{"name": "transfer", "type": "function"}]

        tx_hash = utils.execute_contract_function(
            '0xContractAddress',
            abi,
            'transfer',
            '0xFrom',
            'private_key',
            '0xTo',
            100
        )

        assert tx_hash is not None


class TestUtilityFunctions:
    """Test utility helper functions"""

    @patch('engine.blockchain.web3_utils.Web3')
    def test_checksum_address(self, mock_web3):
        """Should convert to checksum address"""
        mock_w3 = Mock()
        mock_w3.to_checksum_address.return_value = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')
        checksum = utils.to_checksum_address('0x742d35cc6634c0532925a3b844bc9e7595f0beb')

        assert checksum == '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'

    @patch('engine.blockchain.web3_utils.Web3')
    def test_is_address(self, mock_web3):
        """Should validate address format"""
        mock_w3 = Mock()
        mock_w3.is_address.return_value = True
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')
        is_valid = utils.is_address('0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb')

        assert is_valid is True

    @patch('engine.blockchain.web3_utils.Web3')
    def test_wei_to_ether_conversion(self, mock_web3):
        """Should convert Wei to Ether"""
        mock_w3 = Mock()
        mock_w3.from_wei.return_value = 1.0
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')
        ether = utils.wei_to_ether(1000000000000000000)

        assert ether == 1.0

    @patch('engine.blockchain.web3_utils.Web3')
    def test_ether_to_wei_conversion(self, mock_web3):
        """Should convert Ether to Wei"""
        mock_w3 = Mock()
        mock_w3.to_wei.return_value = 1000000000000000000
        mock_web3.return_value = mock_w3

        utils = Web3Utils('http://localhost:8545')
        wei = utils.ether_to_wei(1.0)

        assert wei == 1000000000000000000
