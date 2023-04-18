// // SPDX-License-Identifier: UNLICENSED
// pragma solidity ^0.8.17;

// import "./interfaces/IProxy.sol";

// contract Proxy is IProxy {
//     function proxyCall(address to, uint256 amount, bytes calldata payload) external returns (bytes memory) {
//         (bool success, bytes memory rtn) = payable(to).call{value: amount}(payload);
//         require(success, "");
//         return rtn;
//     }
// }
