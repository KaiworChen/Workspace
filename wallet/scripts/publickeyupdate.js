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

 //const{exponent,modulus} = publicKeyToComponents(publicKey);
 await publicPKeyOrcle.setPublicKey(domain,selector,exponent,modulus);
 


//publicKeyToComponents(password);

// const password = new NodeRSA('-----BEGIN PUBLIC KEY-----'+
//   'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs6VD4JQQHRZ2EZNR50TakIQFY3GGP4VfY3BPbueQe6Xnwvhuh5wkVllU8XTIxxZt+T6ug7tb6QbACupQ9I/TA2dKkiWv4WXUt+qRfkcZvzedEgGJalQLvPR2iZaImqWiMNXOintifm0g88rsfRrYUWa3T+YIo5biIg9Anqmo9wbKDmtMlWMgkoUqKHbjDVgHb6iqYjDV/HEkp5htBCacP5KvdcH18m6P2qUncfxfPj5DkrwyPAk3x4Mp6sm4wqABYyyRukxO2/lIKUjZgbHAEudRG9lZqliykMOA5ZAKQzD0ElWQiYPAK2s95+G0FHd4JWtD5pUqqzuY+hOnm/0dDwIDAQAB'+
//   '-----END PUBLIC KEY-----')
// console.log(password.exportKey("components-public"))

// console.log(publicKeyToComponents(publicKey))

//const newpublickey = parsed.exportKey("components-public")

//const publicKey2=getKey('gmail.com','20221208');

//console.log(publicKey2);
