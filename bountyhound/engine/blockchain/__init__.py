"""
Blockchain & Smart Contract Security Testing Module
"""

from .solidity.contract_analyzer import ContractAnalyzer
from .solidity.slither_runner import SlitherRunner
from .solidity.mythril_runner import MythrilRunner
from .web3_utils import (
    Web3Utils,
    ContractDeployer,
    TransactionAnalyzer,
    EventMonitor
)

__version__ = "1.0.0"

__all__ = [
    'ContractAnalyzer',
    'SlitherRunner',
    'MythrilRunner',
    'Web3Utils',
    'ContractDeployer',
    'TransactionAnalyzer',
    'EventMonitor'
]
