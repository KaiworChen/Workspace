// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";

import "./interfaces/IDKIM.sol";

contract Wallet is Ownable {
    IDKIM public dkim;
    uint public NONCE;

    constructor(address _dkim) {
        dkim = IDKIM(_dkim);
    }

    function generalCall(
        address to,
        uint256 amount,
        bytes calldata payload,
        uint256 nonce,
        bytes calldata sign
    ) external returns (bytes memory) {
        auth(to, amount, nonce, payload, sign);
        return proxyCall(to, amount, payload);
    }

    function proxyCall(
        address to,
        uint256 amount,
        bytes calldata payload
    ) private returns (bytes memory) {
        (bool success, bytes memory rtn) = payable(to).call{value: amount}(
            payload
        );
        require(success, "");
        return rtn;
    }

    function auth(
        address to,
        uint256 amount,
        uint256 nonce,
        bytes calldata payload,
        bytes calldata sign
    ) private view returns (bool) {
        bytes memory data = abi.encode(to, nonce, payload, amount);
        bytes32 hash = keccak256(data);

        address addr = ecrecovery(hash, sign);
        require(addr == owner(), "Auth failed: Only owner!");
        return true;
    }

    function ecrecovery(bytes32 hash, bytes memory signature)
        public
        pure
        returns (address)
    {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "ECDSA signature incorrect");
        return ecrecover(hash, v, r, s);
    }


    function changeKey(bytes calldata raw) external returns (bool) {

         (bool success, string memory body) = dkim.verify(string(raw));
         require(success, "DKIM: verify failed");

         (bytes memory newowner,bytes memory walletaddr,uint nonce) = splitbody(bytes(body));
         require(nonce == NONCE && address(bytes20(walletaddr)) == address(this) ,"Invalid nonce or error address");
         NONCE++;
         transferOwnership(address(bytes20(newowner)));
        return true;
    }

    function splitbody(bytes memory body)  internal pure returns (bytes memory owner, bytes memory contractaddr, uint nonce) { //分割body
        (owner, contractaddr, nonce) = abi.decode(body,(bytes, bytes, uint));
        return (owner, contractaddr, nonce);
    }
}
