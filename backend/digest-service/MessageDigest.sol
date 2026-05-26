// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MessageDigest {
    event DigestRecorded(bytes32 indexed batchHash, uint256 timestamp);

    address public immutable owner;
    mapping(uint256 => bytes32) public batches;
    uint256 public batchCount;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function recordDigest(bytes32 batchHash) external onlyOwner {
        batches[batchCount] = batchHash;
        batchCount++;
        emit DigestRecorded(batchHash, block.timestamp);
    }
}
