// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

interface IDKIM {
    function verify(string memory raw)
        external
        view
        returns (bool, string memory);
}