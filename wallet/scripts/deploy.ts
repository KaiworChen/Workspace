import '@nomiclabs/hardhat-ethers';
import { ethers } from "hardhat";

async function main() {
  const PublicKeyOracle = await ethers.getContractFactory("PublicKeyOracle");
  const publicPKeyOrcle = await PublicKeyOracle.deploy();
  await publicPKeyOrcle.deployed();
  console.log(`PublicKeyOracle deployed at ${publicPKeyOrcle.address}`);

  module.exports = PublicKeyOracle;

  const DKIM = await ethers.getContractFactory("DKIM");
  const dkim = await DKIM.deploy(publicPKeyOrcle.address);
  await dkim.deployed();
  console.log(`DKIM deployed at ${dkim.address}`);

  // const WalletFactory = await ethers.getContractFactory("WalletFactory");
  // const factory = await WalletFactory.deploy();

  // await factory.deployed();
  // console.log(`WalletFactory deployed to ${factory.address}`);

  // const signers = await ethers.getSigners();
  // await factory.createWallet(1, signers[0].address);
  // await factory.createWallet(2, signers[0].address);
}


// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});