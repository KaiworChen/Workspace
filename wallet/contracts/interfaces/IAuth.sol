// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

interface IAuth {
    function auth(address to, uint256 amount, uint256 nonce, bytes calldata payload, bytes calldata sign) external returns (bool);
}