// // SPDX-License-Identifier: UNLICENSED
// pragma solidity ^0.8.17;

// import "./interfaces/IAuth.sol";

// contract Auth is IAuth {
//     address public owner;

//     function auth(
//         address to,
//         uint256 amount,
//         uint256 nonce,
//         bytes calldata payload,
//         bytes calldata sign
//     ) public view override returns (bool) {
//         bytes memory data = abi.encode(to, nonce, payload, amount);
//         bytes32 hash = keccak256(data);

//         address addr = ecrecovery(hash, sign);
//         require(addr == owner, "Auth failed: Only owner!");
//         return true;
//     }

//     function ecrecovery(bytes32 hash, bytes memory signature)
//         public
//         pure
//         returns (address)
//     {
//         bytes32 r;
//         bytes32 s;
//         uint8 v;
//         assembly {
//             r := mload(add(signature, 32))
//             s := mload(add(signature, 64))
//             v := byte(0, mload(add(signature, 96)))
//         }
//         if (v < 27) {
//             v += 27;
//         }
//         require(v == 27 || v == 28, "ECDSA signature incorrect");
//         return ecrecover(hash, v, r, s);
//     }
// }
