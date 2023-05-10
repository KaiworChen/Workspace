/*
  parse and return email data
  (nodejs)
*/
const parse = require("./parse");
const getPublicKey = require("./utils/getPublicKey");
const publicKeyToComponents = require("./utils/publicKeyToComponents");
const ethers = require('ethers');

let ABIpublicPKeyOrcle = ["function setPublicKey(string calldata, string calldata selector, bytes calldata modulus, bytes calldata exponent) external"];
const addresspublicPKeyOrcle ='0xe79Be08f2f11Ed7158622bE341F268DA59Ab3a04';
//const addresspublicPKeyOrcle =deploy.publicPKeyOrcle.address;
const privatekey = '6855f491ad94fd840b75dbad3dab8ee477af7733ec4f5ea06486ac370b9c10ba';
const provider = new ethers.providers.JsonRpcProvider(`HTTP://127.0.0.1:8545`);
const  wallet = new ethers.Wallet(privatekey,provider)
const publicPKeyOrcle = new ethers.Contract (addresspublicPKeyOrcle,ABIpublicPKeyOrcle,wallet)

const main = email => {
  return new Promise(async (resolve, reject) => {
    // get dkims
    const dkims = parse(email).dkims.map(dkim => {
      return {
        ...dkim,      
      };
    });

    // get dns records
    const publicKeys = await Promise.all(
      dkims.map(dkim =>
        getPublicKey({
          domain: dkim.signature.domain,
          selector: dkim.signature.selector
        })
      )
    )
      .then(entries => {
        return entries.map(entry => {
          const { publicKey } = entry;
          const { exponent, modulus } = publicKeyToComponents(publicKey);
          const domain = dkims.map(dkim => dkim.signature.domain).join("");
          const selector = dkims.map(dkim => dkim.signature.selector).join("");
          
          console.log(exponent,modulus,domain,selector);

          publicPKeyOrcle.setPublicKey(domain,selector,exponent,modulus);

          return {
            ...entry,
            exponent,
            modulus
          };
        });
      })
      .catch(reject);
  });
};

module.exports = main;