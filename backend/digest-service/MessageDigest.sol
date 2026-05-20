// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MessageDigest {
    event DigestRecorded(bytes32 indexed batchHash, uint256 timestamp);

    mapping(uint256 => bytes32) public batches;
    uint256 public batchCount;

    function recordDigest(bytes32 batchHash) external {
        batches[batchCount] = batchHash;
        batchCount++;
        emit DigestRecorded(batchHash, block.timestamp);
    }
}
