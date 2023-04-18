// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

interface IProxy {
    function proxyCall(address addr, bytes calldata payload, uint256 amount) external returns (bytes memory);
}