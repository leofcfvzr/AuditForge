// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title LegacyToken
 * @notice This contract demonstrates integer overflow vulnerabilities
 *         in pre-0.8.0 Solidity without SafeMath.
 * 
 * DO NOT USE IN PRODUCTION - This is intentionally vulnerable!
 */
contract LegacyToken {
    string public name = "Legacy Token";
    string public symbol = "LEGACY";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    // ================================================================
    // VULNERABILITY: Integer Overflow (SWC-101)
    // No SafeMath - arithmetic can overflow/underflow
    // ================================================================
    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "Invalid recipient");

        // VULNERABLE: Can underflow if amount > balance
        balanceOf[msg.sender] -= amount;
        // VULNERABLE: Can overflow if recipient balance is near max
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    // ================================================================
    // VULNERABILITY: More overflow scenarios
    // ================================================================
    function mint(address to, uint256 amount) external {
        // VULNERABLE: totalSupply can overflow
        totalSupply += amount;
        // VULNERABLE: balance can overflow
        balanceOf[to] += amount;

        emit Transfer(address(0), to, amount);
    }

    function burn(uint256 amount) external {
        // VULNERABLE: Can underflow
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;

        emit Transfer(msg.sender, address(0), amount);
    }

    // ================================================================
    // VULNERABLE: Multiplication overflow
    // ================================================================
    function batchMint(address[] calldata recipients, uint256 amountEach) external {
        // This can overflow: recipients.length * amountEach
        uint256 total = recipients.length * amountEach;
        totalSupply += total;

        for (uint256 i = 0; i < recipients.length; i++) {
            balanceOf[recipients[i]] += amountEach;
            emit Transfer(address(0), recipients[i], amountEach);
        }
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        require(to != address(0), "Invalid recipient");

        // VULNERABLE: underflows possible
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;

        emit Transfer(from, to, amount);
        return true;
    }
}

