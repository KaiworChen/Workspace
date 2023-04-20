// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./DKIM.sol";



contract Wallet is Ownable {
     using DKIM for *;
    // function generalCall(
    //     address to,
    //     uint256 amount,
    //     bytes calldata payload,
    //     uint256 nonce,
    //     bytes calldata sign
    // ) external returns (bytes memory) {
    //     auth(to, amount, nonce, payload, sign);
    //     return proxyCall(to, amount, payload);
    // }

    // function proxyCall(
    //     address to,
    //     uint256 amount,
    //     bytes calldata payload
    // ) private returns (bytes memory) {
    //     (bool success, bytes memory rtn) = payable(to).call{value: amount}(
    //         payload
    //     );
    //     require(success, "");
    //     return rtn;
    // }

    // function auth(
    //     address to,
    //     uint256 amount,
    //     uint256 nonce,
    //     bytes calldata payload,
    //     bytes calldata sign
    // ) private view returns (bool) {
    //     bytes memory data = abi.encode(to, nonce, payload, amount);
    //     bytes32 hash = keccak256(data);

    //     address addr = ecrecovery(hash, sign);
    //     require(addr == owner(), "Auth failed: Only owner!");
    //     return true;
    // }

    // function ecrecovery(bytes32 hash, bytes memory signature)
    //     public
    //     pure
    //     returns (address)
    // {
    //     bytes32 r;
    //     bytes32 s;
    //     uint8 v;
    //     assembly {
    //         r := mload(add(signature, 32))
    //         s := mload(add(signature, 64))
    //         v := byte(0, mload(add(signature, 96)))
    //     }
    //     if (v < 27) {
    //         v += 27;
    //     }
    //     require(v == 27 || v == 28, "ECDSA signature incorrect");
    //     return ecrecover(hash, v, r, s);
    // }


    //function changeKey(bytes calldata email) external returns (bool) {
        // owner = verifyDKIM(email);
    //}

    uint public NONCE = 0;

    function verifyDKIM(bytes calldata email) internal returns (address) {
        bytes memory newowner; //公钥 
        bytes memory contractaddr; //合约账户
        uint nonce; //nonce值
        string memory bodytemp;
        uint success = 0;
        
        (success, bodytemp) =string(email).verify();

        if(success == 1) {
            (newowner, contractaddr, nonce) = splitbody(bytes(bodytemp));
            // 验证owner、nonce等值
            if(nonce == NONCE){ //验证nonce，防止重放。
                require (address(bytes20(contractaddr)) == address(this),"error address"); //验证合约地址
                NONCE++;
                return address(bytes20(newowner));
            }
        } else {
            return address(0x0);
        }

    }

    function splitbody(bytes memory body) internal pure returns (bytes memory owner, bytes memory contractaddr, uint nonce) { //分割body
        (owner, contractaddr, nonce) = abi.decode(body,(bytes, bytes, uint));
        return (owner, contractaddr, nonce);
    }
}