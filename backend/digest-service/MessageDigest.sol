// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MessageDigest {
    event DigestRecorded(bytes32 indexed batchHash, uint256 timestamp);

    address public immutable owner;

    // `batches` stores every batch hash by sequential index on-chain so they
    // can be enumerated via eth_call without replaying event logs.
    // The `DigestRecorded` event (below) marks batchHash as `indexed` so it
    // appears in topics[1] of the tx receipt — this is what the verification
    // page reads to confirm the hash without trusting the app server's DB.
    // Both routes reach the same on-chain value; they serve different callers.
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
