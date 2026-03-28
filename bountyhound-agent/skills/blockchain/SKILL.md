---
name: blockchain
description: "Smart contract auditing, DeFi exploit detection, NFT security, bridge vulnerabilities, and on-chain attack patterns"
difficulty: advanced
bounty_range: "$5,000 - $500,000+"
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Blockchain Security Testing

## Smart Contract Vulnerabilities

### Reentrancy Attacks

The most infamous smart contract vulnerability. Occurs when an external call is made before state updates.

**Classic reentrancy:**
```solidity
// VULNERABLE - state update after external call
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;  // Too late!
}

// EXPLOIT CONTRACT
contract Attacker {
    function attack() external payable {
        victim.deposit{value: 1 ether}();
        victim.withdraw(1 ether);
    }

    receive() external payable {
        if (address(victim).balance >= 1 ether) {
            victim.withdraw(1 ether);  // Re-enter before balance updated
        }
    }
}
```

**Cross-function reentrancy:**
```solidity
// withdraw() and transfer() share state but don't guard each other
function withdraw() public {
    uint amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] = 0;
}

function transfer(address to, uint amount) public {
    if (balances[msg.sender] >= amount) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
// Attacker re-enters via transfer() during withdraw() callback
```

**Read-only reentrancy:**
```solidity
// View function returns stale state during reentrancy
function getPrice() public view returns (uint) {
    return totalAssets / totalShares;  // Stale during callback
}
// Another protocol reads this price mid-reentrancy = manipulated price
```

**Detection patterns:**
- External calls before state changes (checks-effects-interactions violation)
- Missing reentrancy guards (`nonReentrant` modifier)
- Cross-contract calls that share state
- View functions consumed by other protocols during state transitions

### Integer Overflow/Underflow

**Pre-Solidity 0.8.0 (no built-in overflow protection):**
```solidity
// VULNERABLE
uint8 balance = 255;
balance += 1;  // Wraps to 0

uint8 balance = 0;
balance -= 1;  // Wraps to 255

// EXPLOIT: bypass balance checks
function transfer(address to, uint256 amount) public {
    require(balances[msg.sender] - amount >= 0);  // Always true with underflow!
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

**Post-0.8.0 bypass via unchecked blocks:**
```solidity
// Devs sometimes use unchecked for gas optimization
unchecked {
    balance -= amount;  // Can still underflow!
}
```

**Detection:**
- Solidity version < 0.8.0 without SafeMath
- `unchecked` blocks with arithmetic on user-controlled values
- Type casting between different-sized integers

### Access Control Flaws

**Missing access control:**
```solidity
// VULNERABLE - anyone can call
function setAdmin(address newAdmin) public {
    admin = newAdmin;
}

// VULNERABLE - tx.origin instead of msg.sender
function transferOwnership(address newOwner) public {
    require(tx.origin == owner);  // Phishing attack via intermediary contract
    owner = newOwner;
}
```

**tx.origin phishing attack:**
```solidity
// Attacker deploys this and tricks owner into calling it
contract Phisher {
    function claimReward() external {
        // tx.origin = victim (who initiated the tx)
        // msg.sender = this contract
        victim_contract.transferOwnership(attacker);  // tx.origin check passes
    }
}
```

**Unprotected initializers (proxy patterns):**
```solidity
// VULNERABLE - initializer can be called by anyone
function initialize(address _admin) public {
    admin = _admin;
}
// Missing: require(!initialized) or OpenZeppelin's initializer modifier
```

**Detection patterns:**
- Functions missing `onlyOwner`/`onlyAdmin` modifiers
- `tx.origin` used for authorization
- Unprotected `initialize()` in proxy contracts
- `selfdestruct` callable by non-owners
- Missing role checks on privileged operations

### Delegatecall Vulnerabilities

```solidity
// VULNERABLE - delegatecall preserves caller's storage layout
contract Proxy {
    address public implementation;  // slot 0
    address public owner;          // slot 1

    fallback() external payable {
        (bool success,) = implementation.delegatecall(msg.data);
    }
}

contract Implementation {
    address public someAddress;  // slot 0 - OVERWRITES implementation!

    function setAddress(address _addr) public {
        someAddress = _addr;  // Actually overwrites Proxy.implementation
    }
}
```

### Frontrunning / MEV

```
Detection:
- Transactions with predictable profitable outcomes
- Missing commit-reveal schemes
- No slippage protection on DEX trades
- Oracle updates without delay mechanisms

Common targets:
- DEX trades without slippage limits
- NFT mints with known rarity
- Liquidation calls in lending protocols
- Governance vote outcomes
```

## DeFi Exploit Patterns

### Flash Loan Attacks

**Attack template:**
```
1. Borrow massive amount via flash loan (no collateral needed)
2. Use borrowed funds to manipulate price/state
3. Exploit the manipulated state for profit
4. Repay flash loan + fee
5. Keep profit

Platforms: Aave, dYdX, Balancer, Uniswap V3
Loan sizes: Up to hundreds of millions in a single tx
```

**Price oracle manipulation via flash loan:**
```solidity
// VULNERABLE - spot price as oracle
function getPrice() public view returns (uint) {
    // Uses current pool reserves - manipulable via flash loan
    (uint reserve0, uint reserve1,) = pair.getReserves();
    return reserve0 * 1e18 / reserve1;
}

// ATTACK FLOW:
// 1. Flash loan large amount of tokenA
// 2. Swap tokenA for tokenB on Uniswap (moves spot price)
// 3. Interact with vulnerable protocol that reads manipulated price
// 4. Profit from mispriced assets
// 5. Swap back, repay flash loan
```

**Detection:**
- Protocols using spot prices from AMMs as oracles
- No TWAP (time-weighted average price) usage
- Single-block price reads
- Missing flash loan guards (`block.number` checks)

### Sandwich Attacks

```
MEMPOOL MONITORING:
1. Detect victim's pending DEX swap in mempool
2. Front-run: buy the same token (raises price)
3. Victim's swap executes at worse price
4. Back-run: sell the token at inflated price
5. Profit = victim's slippage

DETECTION IN CONTRACTS:
- Missing minimum output amount (slippage protection)
- No deadline parameter on swaps
- Large swaps without MEV protection (Flashbots, private mempool)
```

### Rug Pull Detection

**Red flags in contract code:**
```solidity
// DANGEROUS: Owner can drain all funds
function emergencyWithdraw() external onlyOwner {
    payable(owner).transfer(address(this).balance);
}

// DANGEROUS: Owner can mint unlimited tokens
function mint(address to, uint amount) external onlyOwner {
    _mint(to, amount);
}

// DANGEROUS: Hidden transfer fee / tax manipulation
function setTaxRate(uint newRate) external onlyOwner {
    taxRate = newRate;  // Can set to 99%
}

// DANGEROUS: Blacklist function prevents selling
function setBlacklist(address user, bool status) external onlyOwner {
    blacklisted[user] = status;
}

// DANGEROUS: Proxy can be upgraded to malicious implementation
function upgradeTo(address newImpl) external onlyOwner {
    implementation = newImpl;  // Can swap to drain contract
}
```

**Liquidity rug indicators:**
- LP tokens not locked or burned
- Owner holds majority of LP tokens
- No timelock on admin functions
- Migrator function that can move liquidity

### Governance Attacks

```
FLASH LOAN GOVERNANCE:
1. Flash loan governance tokens
2. Create and vote on malicious proposal
3. Proposal passes (attacker has majority)
4. Execute proposal (drain treasury)
5. Return governance tokens

DETECTION:
- No snapshot mechanism for voting power
- Voting power checked at vote time, not proposal time
- No time delay between proposal and execution
- Low quorum requirements
```

## NFT Security

### Lazy Minting Exploits

```solidity
// VULNERABLE - predictable tokenId allows frontrunning rare NFTs
function lazyMint(uint tokenId, bytes memory signature) public payable {
    require(verify(tokenId, signature), "Invalid signature");
    _mint(msg.sender, tokenId);
}
// Attacker sees pending mint tx, identifies rare tokenId, frontruns with same signature
```

### Metadata Manipulation

```
CENTRALIZED METADATA RISKS:
- Off-chain metadata on HTTP servers (can be changed post-mint)
- IPFS without content pinning
- Centralized API that resolves tokenURI (single point of failure)

TESTING:
1. Check if tokenURI points to centralized server
2. Check if baseURI can be changed by owner post-mint
3. Check if metadata is on IPFS with pinning
4. Check if token reveals are manipulable
```

### Royalty Bypass

```
EIP-2981 royalties are OPTIONAL - marketplaces can ignore them

COMMON BYPASSES:
1. Transfer via direct ERC-721 transfer (no marketplace = no royalty)
2. Wrapper contracts that hold NFT and sell wrapper token
3. OTC trades via escrow contracts
4. Marketplaces that don't enforce EIP-2981 (Blur, SudoSwap)
```

### Minting Vulnerabilities

```solidity
// VULNERABLE - no per-wallet limit
function mint(uint amount) public payable {
    require(totalSupply + amount <= maxSupply);
    require(msg.value >= price * amount);
    _mint(msg.sender, amount);
}
// Attacker mints all from contract, bypasses "per wallet" limits

// VULNERABLE - weak randomness for rarity
function _getTraits(uint tokenId) internal view returns (uint) {
    return uint(keccak256(abi.encodePacked(block.timestamp, tokenId))) % 100;
    // Predictable - miner/validator can manipulate block.timestamp
}
```

## Bridge Vulnerabilities

### Cross-Chain Relay Attacks

```
COMMON BRIDGE ARCHITECTURE:
Chain A → Lock tokens → Emit event → Relayer picks up → Chain B → Mint wrapped tokens

ATTACK VECTORS:
1. Fake deposit events (insufficient event verification)
2. Replay attacks (same proof used on multiple chains)
3. Relayer manipulation (compromised validator set)
4. Signature verification bypass
5. Incorrect chain ID validation
```

### Signature Verification Flaws

```solidity
// VULNERABLE - missing chain ID in signed message
function claim(uint amount, bytes memory signature) public {
    bytes32 hash = keccak256(abi.encodePacked(amount, msg.sender));
    require(recover(hash, signature) == validator);
    // Missing: chain ID, nonce, contract address in hash
    // Same signature valid on all chains!
}

// VULNERABLE - ecrecover returns address(0) on invalid signature
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
    address signer = ecrecover(hash, v, r, s);
    // Missing: require(signer != address(0))
    // If signer mapping has address(0) as valid, attacker bypasses
}
```

### Bridge-Specific Testing

```
CHECKLIST:
[ ] Verify deposit event authenticity (block hash, tx proof)
[ ] Check for replay protection (nonces, chain IDs)
[ ] Validate signature scheme (threshold, key rotation)
[ ] Test message ordering assumptions
[ ] Check withdrawal delay / challenge period
[ ] Verify upgrade mechanisms (proxy patterns)
[ ] Test admin key security (multisig, timelock)
[ ] Verify merkle proof validation
```

## Common Solidity Anti-Patterns

### Dangerous Patterns

```solidity
// 1. Unprotected selfdestruct
function kill() public { selfdestruct(payable(owner)); }

// 2. Block timestamp dependence for randomness
uint random = uint(keccak256(abi.encodePacked(block.timestamp)));

// 3. Unchecked return value on low-level calls
address(target).call{value: amount}("");  // Ignored return value

// 4. Storage collision in proxy patterns
// Implementation slot 0 != Proxy slot 0

// 5. Denial of service via unbounded loops
function distributeRewards() public {
    for (uint i = 0; i < holders.length; i++) {  // Unbounded!
        holders[i].transfer(rewards[i]);
    }
}

// 6. Force-feeding ETH via selfdestruct
// Contract assumes address(this).balance == tracked deposits
// Attacker selfdestructs contract with ETH to this address

// 7. Signature malleability
// ECDSA signatures have two valid forms (s, n-s)
// Missing: require(s <= N/2) or use OpenZeppelin ECDSA
```

### Safe Patterns

```solidity
// Checks-Effects-Interactions
function withdraw(uint amount) public nonReentrant {
    require(balances[msg.sender] >= amount);   // Check
    balances[msg.sender] -= amount;            // Effect
    (bool success, ) = msg.sender.call{value: amount}("");  // Interaction
    require(success);
}

// Pull over Push for payments
mapping(address => uint) public pendingWithdrawals;
function withdraw() public {
    uint amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}

// Use Chainlink VRF for randomness
// Use OpenZeppelin's AccessControl for roles
// Use UUPS or Transparent proxy patterns correctly
// Use SafeERC20 for token interactions
```

## Testing Tools

### Static Analysis

```bash
# Slither - comprehensive static analyzer
slither ./contracts/ --print human-summary
slither ./contracts/ --detect reentrancy-eth,reentrancy-no-eth
slither ./contracts/ --detect arbitrary-send-erc20
slither ./contracts/ --detect suicidal
slither ./contracts/ --detect unprotected-upgrade

# Common high-confidence detectors:
# reentrancy-eth          - Reentrancy with ETH transfer
# arbitrary-send-erc20    - Unprotected token transfer
# suicidal                - Unprotected selfdestruct
# controlled-delegatecall - Delegatecall to user-controlled address
# uninitialized-state     - Uninitialized state variables
```

### Symbolic Execution

```bash
# Mythril - symbolic execution engine
myth analyze ./contracts/Vulnerable.sol
myth analyze ./contracts/Vulnerable.sol --execution-timeout 300
myth analyze --solc-json mythril.config.json

# Manticore - symbolic execution framework
manticore ./contracts/Vulnerable.sol --contract Vulnerable
```

### Fuzzing

```bash
# Echidna - property-based fuzzer
echidna ./contracts/Test.sol --contract TestContract --config echidna.yaml

# Example property test:
# function echidna_balance_invariant() public returns (bool) {
#     return address(this).balance >= totalDeposits;
# }

# Foundry Fuzz Testing
forge test --fuzz-runs 10000
# function testFuzz_withdraw(uint256 amount) public {
#     vm.assume(amount <= address(vault).balance);
#     vault.withdraw(amount);
#     assertEq(address(vault).balance, initialBalance - amount);
# }
```

### Development & Testing Frameworks

```bash
# Foundry - fast Solidity testing framework
forge build          # Compile
forge test -vvvv     # Test with max verbosity
forge test --gas-report
forge inspect Contract storage-layout

# Hardhat
npx hardhat compile
npx hardhat test
npx hardhat run scripts/exploit.js --network fork

# Fork mainnet for testing against live state
forge test --fork-url https://eth-mainnet.alchemyapi.io/v2/KEY
anvil --fork-url https://eth-mainnet.alchemyapi.io/v2/KEY
```

### On-Chain Analysis

```bash
# Etherscan source verification
# Check if source matches bytecode
# Look for proxy patterns and implementation contracts

# Tenderly - transaction simulation and debugging
# Simulate transactions before sending
# Debug failed transactions with stack traces

# Dune Analytics / Nansen - on-chain behavior analysis
# Track fund flows and whale movements
```

## Evidence Requirements

### Smart Contract Vulnerability Report

```
REQUIRED EVIDENCE:
1. Vulnerable contract address and function
2. Solidity source code with vulnerability highlighted
3. Exploit contract or script (Foundry/Hardhat test)
4. Step-by-step reproduction:
   a. Deploy exploit contract
   b. Call vulnerable function
   c. Show state change (funds drained, access escalated)
5. Mainnet fork proof (demonstrate on forked state)
6. Impact calculation (TVL at risk, affected users)
7. Suggested fix with corrected code

FORMAT:
- Foundry test file with POC
- Transaction trace showing exploit flow
- Before/after balance comparison
- Gas cost of attack
```

### DeFi Exploit Report

```
REQUIRED EVIDENCE:
1. Attack transaction flow (step by step)
2. Flash loan source and amount
3. Affected pools/protocols
4. Price impact calculation
5. Profit calculation
6. Foundry/Hardhat POC on mainnet fork
7. TVL at risk and historical TVL data
```

## Bounty Ranges

| Vulnerability | Typical Range | Top Payouts |
|--------------|---------------|-------------|
| Reentrancy (critical) | $10,000 - $100,000 | $500,000+ (Immunefi) |
| Flash loan oracle manipulation | $20,000 - $200,000 | $1,000,000+ |
| Bridge signature bypass | $50,000 - $500,000 | $2,000,000+ (Wormhole) |
| Access control (admin functions) | $5,000 - $50,000 | $250,000 |
| Integer overflow (fund loss) | $5,000 - $100,000 | $500,000 |
| Governance attack | $10,000 - $150,000 | $500,000 |
| NFT minting exploit | $5,000 - $25,000 | $50,000 |
| Front-running / MEV | $5,000 - $50,000 | $100,000 |
| Proxy storage collision | $10,000 - $100,000 | $250,000 |
| Logic error (fund drainage) | $10,000 - $500,000 | $10,000,000 (Immunefi max) |

### Key Platforms

```
Immunefi     - Largest Web3 bug bounty platform, $100M+ in bounties
Code4rena    - Competitive audit contests, $25K-$1M+ prize pools
Sherlock     - Protocol audit contests with staking
HackerOne    - Some Web3 programs (Coinbase, Crypto.com)
Bugcrowd     - Limited Web3 programs
Direct       - Protocol-specific programs (Uniswap, Aave, MakerDAO)
```

## Real-World Examples

```
The DAO Hack (2016):
- Reentrancy attack drained 3.6M ETH (~$60M at time)
- Led to Ethereum hard fork (ETH/ETC split)
- Classic checks-effects-interactions violation

Wormhole Bridge (2022):
- Signature verification bypass
- 120,000 wETH stolen (~$320M)
- Attacker forged guardian signatures

Beanstalk Governance (2022):
- Flash loan governance attack
- $182M drained via malicious proposal
- Borrowed governance tokens, voted, executed, returned

Ronin Bridge (2022):
- Compromised validator keys (5 of 9)
- 173,600 ETH + 25.5M USDC stolen (~$620M)
- Social engineering + insufficient key management

Euler Finance (2023):
- Flash loan + donation attack
- $197M stolen (later returned)
- Manipulated internal accounting via forced donation
```
