const NodeRSA = require("node-rsa");
const { promisify } = require("util");
const getKey = promisify(require("dkim/lib/get-key"));
const ethers = require('ethers');

let ABIpublicPKeyOrcle = ["function setPublicKey(string calldata, string calldata selector, bytes calldata modulus, bytes calldata exponent) external onlyOwner"];

const addresspublicPKeyOrcle ="";

const provider = new ethers.providers.JsonRpcProvider(`"http://localhost:8545"`);

const publicPKeyOrcle = new ethers.Contract (addresspublicPKeyOrcle,ABIpublicPKeyOrcle,provider);

const getPublicKey = ({ domain, selector }) => {
  return getKey(domain, selector).then(key => {
    const publicKey =
      "-----BEGIN PUBLIC KEY-----\n" +
      key.key.toString("base64") +
      "\n-----END PUBLIC KEY-----";
    return {
        domain,
        selector,
        publicKey
      };
    });
  };

const publicKeyToComponents = publicKey => {
  const parsed = new NodeRSA(publicKey);

  const { e: exponent, n: modulus } = parsed.exportKey("components-public");

  console.log(exponent,modulus)

   return {
    exponent,
     modulus
 };
};

 const {domain, selector,exponent,modulus} = getPublicKey({domain:'gmail.com',selector:'20221208'})
 .then (publicKey=>{publicKeyToComponents(publicKey)});

 await publicPKeyOrcle.setPublicKey(domain,selector,exponent,modulus);
 
