import '@nomiclabs/hardhat-ethers';
import { ethers } from "hardhat";

async function main() {
  const WalletFactory = await ethers.getContractFactory("WalletFactory");
  const factory = await WalletFactory.deploy();

  await factory.deployed();
  console.log(`WalletFactory deployed to ${factory.address}`);

  const signers = await ethers.getSigners();
  await factory.createWallet(1, signers[0].address);
  await factory.createWallet(2, signers[0].address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
