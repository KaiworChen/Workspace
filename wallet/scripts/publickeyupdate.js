const NodeRSA = require("node-rsa");
const { promisify } = require("util");
const getKey = promisify(require("dkim/lib/get-key"));
const ethers = require('ethers');
//const deploy = require('deploy');

let ABIpublicPKeyOrcle = ["function setPublicKey(string calldata, string calldata selector, bytes calldata modulus, bytes calldata exponent) external"];

const addresspublicPKeyOrcle ='0x624F495fb9d0382f27F085175E4D19db21579b98';

//const addresspublicPKeyOrcle =deploy.publicPKeyOrcle.address;
const privatekey = '6855f491ad94fd840b75dbad3dab8ee477af7733ec4f5ea06486ac370b9c10ba';

const provider = new ethers.providers.JsonRpcProvider(`HTTP://127.0.0.1:8545`);
const  wallet = new ethers.Wallet(privatekey,provider)

const publicPKeyOrcle = new ethers.Contract (addresspublicPKeyOrcle,ABIpublicPKeyOrcle,wallet)

const getPublicKey = async({ domain, selector }) => {
    return getKey(domain, selector).then(key => {
      const publicKey =
        "-----BEGIN PUBLIC KEY-----\n" +
        key.key.toString("base64") +
        "\n-----END PUBLIC KEY-----";
        // console.log(publicKey)
      const parsed = new NodeRSA(publicKey);
      const { e: exponent, n: modulus } =  parsed.exportKey("components-public");
      
      return {
           domain,
          selector,
          exponent,
          modulus,
        };
      });
    };
async function  test() { //test解决异步问题
  const {domain, selector,exponent,modulus} = await getPublicKey({domain:'yahoo.com',selector:'s2048'})
  publicPKeyOrcle.setPublicKey(domain,selector,exponent,modulus);
  console.log(domain,selector,exponent,modulus)
}
  test()
