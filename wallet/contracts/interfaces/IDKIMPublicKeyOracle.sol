// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

interface IDKIMPublicKeyOracle {
    function setPublicKey(
        string calldata domain,
        string calldata selector,
        bytes calldata modulus,
        bytes calldata exponent
    ) external;

    function getRSAKey(string memory domain, string memory selector)
        external
        view
        returns (bytes memory modulus, bytes memory exponent);
}