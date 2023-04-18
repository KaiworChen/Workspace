// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "./Wallet.sol";

contract WalletFactory {
    event WalletCreated(address indexed owner, address contractAddress);
    
    function createWallet(uint256 salt, address owner) external returns (address) {
        address addr = deploy(getBytecode(), salt);
        Wallet(addr).transferOwnership(owner);
        emit WalletCreated(owner, addr);
        return addr;
    }

    function getBytecode() public pure returns (bytes memory) {
        bytes memory bytecode = type(Wallet).creationCode;
        return abi.encodePacked(bytecode);
    }

    function getAddress(bytes memory bytecode, uint _salt)
        public
        view
        returns (address)
    {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                _salt,
                keccak256(bytecode)
            )
        );
        return address(uint160(uint256(hash)));
    }

    function deploy(bytes memory bytecode, uint256 _salt)
        public
        payable
        returns (address)
    {
        address addr;
        /*
          how to call create
          create2(v,p,n,s)
          v amount of eth to send
          p pointer to start of code in memory
          n size of code
          s salt
         */
        assembly {
            addr := create2(
                // weisent with current call
                callvalue(),
                add(bytecode, 0x20),
                mload(bytecode),
                _salt
            )
        }
        return addr;
    }
}
