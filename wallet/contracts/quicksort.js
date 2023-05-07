/*
  use parse-email lib to verify an email with nodejs crypto
  used for testing
*/
const crypto = require("crypto");
const fs = require("fs");
const parseEmail = require("../parse-email/node");

const [, , path] = process.argv;

const verifyEmail = path => {
  return new Promise(async (resolve, reject) => {
    const email = fs.readFileSync(path, {
      encoding: "ascii"
    });

    const dkims = await parseEmail(email).catch(reject);

    const results = dkims.map((dkim, i) => {
      const verified = crypto
        .createVerify(dkim.algorithm)
        .update(dkim.processedHeader)
        .verify(dkim.publicKey, dkim.signature.signature);

      return { name: dkim.entry.name, verified };
    });

    return resolve(results);
  });
};

if (typeof path === "undefined") {
  throw Error("no path specified");
}

verifyEmail(path)
  .then(console.log)
  .catch(console.error);

  pragma solidity ^0.8.0;

// 引入可信的预言机合约
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract DNSOracle {
    // 定义预言机合约的地址
    AggregatorV3Interface internal priceFeed;

    // 定义合约函数用于接收预言机响应
    function getDNSPublicKey(uint _domain) public {
        // 向预言机请求DNS中的DKIM的publickey的值，并转换查询信息成预言机查询格式
        bytes32 jobId = "JOB_ID";
        string memory url = string(abi.encodePacked("https://dns.domain.com/dkim/", _domain, "/publickey"));
        Chainlink.Request memory req = buildChainlinkRequest(jobId, address(this), this.fulfillDNSPublicKey.selector);
        req.add("get", url);
        req.add("path", "publickey");

        // 发送查询请求给预言机合约
        sendChainlinkRequestTo(address(priceFeed), req, 1 ether);
    }

    // 处理预言机响应并获取DNS中的DKIM的publickey的值
    function fulfillDNSPublicKey(bytes32 _requestId, bytes32 _dnsPublicKey) public recordChainlinkFulfillment(_requestId) {
        // 处理预言机响应信息，获取DNS中的DKIM的publickey的值
        string memory dnsPublicKey = bytes32ToString(_dnsPublicKey);
        // 在这里进行进一步处理或使用dnsPublicKey值
        // ...
    }
    
    // 将bytes32类型转换成string类型
    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        bytes memory bytesString = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            byte char = byte(bytes32(uint(_bytes32) * 2 ** (8 * j)));
            if (char != 0) {
                bytesString[j] = char;
            }
        }
        return string(bytesString);
    }
}
