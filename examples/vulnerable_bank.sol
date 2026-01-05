// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title VulnerableBank
 * @notice This contract demonstrates multiple security vulnerabilities
 *         for testing AuditForge detection capabilities.
 * 
 * DO NOT USE IN PRODUCTION - This is intentionally vulnerable!
 */
contract VulnerableBank {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => bool) public authorized;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // ================================================================
    // VULNERABILITY: Reentrancy (SWC-107)
    // The state is updated AFTER the external call
    // ================================================================
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // External call BEFORE state update - vulnerable to reentrancy!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call
        balances[msg.sender] = 0;

        emit Withdrawal(msg.sender, amount);
    }

    // ================================================================
    // VULNERABILITY: Missing Access Control (SWC-105)
    // Anyone can call this function
    // ================================================================
    function setOwner(address newOwner) external {
        // No access control - anyone can take ownership!
        owner = newOwner;
    }

    // ================================================================
    // VULNERABILITY: tx.origin Authentication (SWC-115)
    // Using tx.origin for auth is vulnerable to phishing
    // ================================================================
    function withdrawTo(address recipient) external {
        require(tx.origin == owner, "Not owner");
        uint256 balance = address(this).balance;
        payable(recipient).transfer(balance);
    }

    // ================================================================
    // VULNERABILITY: Unchecked Return Value (SWC-104)
    // The return value of send() is not checked
    // ================================================================
    function unsafeSend(address payable recipient, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        // Return value ignored - transfer may silently fail!
        recipient.send(amount);
    }

    // ================================================================
    // SAFE FUNCTION: Proper implementation
    // ================================================================
    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // ================================================================
    // SAFE FUNCTION: Proper CEI pattern
    // ================================================================
    function safeWithdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // State update BEFORE external call (CEI pattern)
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

