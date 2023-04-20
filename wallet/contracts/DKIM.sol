// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "./utils/Strings.sol";
import "./Algorithm.sol";

library DKIM {
    using strings for *;
    //匹配域名字段domin，和选择器 服务类型，selector  没有就返回空值。
    function getRSAKey(strings.slice memory domain, strings.slice memory selector) internal pure returns (bytes memory modulus, bytes memory exponent) {
        if ("fusemachines.com".toSlice().equals(domain) && "google".toSlice().equals(selector)) {
            modulus = hex"9157daff5eb845df246f5e315144ff112ac4f7caa555ad9185620b0a2e5ffb7b14492417c804f23e9d1ce90b5a6ee5719465a85e1ad8ff9b558353d4eb14ae3022f2ef2b25fae5e78fc37c0db1431524fefa6da783b62950694939e623caab7873a110cff9bb848f43e58afcfcb14de54af4f1fd3939e2472c6b9514f174e955";
            exponent = hex"010001";
            return (modulus, exponent);
        }
        if ("gmail.com".toSlice().equals(domain) && "20161025".toSlice().equals(selector)) {
            modulus = hex"be23c6064e1907ae147d2a96c8089c751ee5a1d872b5a7be11845056d28384cfb59978c4a91b4ffe90d3dec0616b3926038f27da4e4d254c8c1283bc9dcdabeac500fbf0e89b98d1059a7aa832893b08c9e51fcea476a69511be611250a91b6a1204a22561bb87b79f1985a687851184533d93dfab986fc2c02830c7b12df9cf0e3259e068b974e3f6cf99fa63744c8b5b23629a4efad425fa2b29b3622443373d4c389389ececc5692e0f15b54b9f49b999fd0754db41a4fc16b8236f68555f9546311326e56c1ea1fe858e3c66f3a1282d440e3b487579dd2c198c8b15a5bab82f1516f48c4013063319c4a06789f943c5fc4e7768c2c0d4ce871c3c51a177";
            exponent = hex"010001";
            return (modulus, exponent);
        }
        if ("protonmail.com".toSlice().equals(domain) && "default".toSlice().equals(selector)) {
            modulus = hex"ca678aeacca0caadf24728d7d3821d41ff736da07ad1f13e185d3b8796da4526585cf867230c4a5fdadbf31e747b47b11b84e762c32e122e0097a8421141eeecc0e4fcbeae733d9ebf239d28f22b31cf9d10964bcda085b27a2350aa50cf40b41ecb441749f2f39d063f6c7c6f280a808b7dc2087c12fce3eeb96707abc0c2a9";
            exponent = hex"010001";
            return (modulus, exponent);
        }
        if ("yahoo.com".toSlice().equals(domain) && "s2048".toSlice().equals(selector)) {
            modulus = hex"ba85ae7e06d6c39f0c7335066ccbf5efa45ac5d64638c9109a7f0e389fc71a843a75a95231688b6a3f0831c1c2d5cb9b271da0ce200f40754fb4561acb22c0e1ac89512364d74feea9f072894f2a88f084e09485ae9c5f961308295e1bb7e835b87c3bc0bce0b827f8600a11e97c54291b00a07ba817b33ebfa6cc67f5f51bebe258790197851f80943a3bc17572428aa19e4aa949091f9a436aa6e0b3e1773e9ca201441f07a104cce03528c3d15891a9ce03ed2a8ba40dc42e294c3d180ba5ee4488c84722ceaadb69428d2c6026cf47a592a467cc8b15a73ea3753d7f615e518ba614390e6c3796ea37367c4f1a109646d5472e9e28e8d49e84924e648087";
            exponent = hex"010001";
            return (modulus, exponent);
        }
        if ("outlook.com".toSlice().equals(domain) && "selector1".toSlice().equals(selector)) {
            modulus = hex"bd6ca4b6b20bf033bff941af31bbfb70f77f5e88296ecee9815c3ccbd95d3ba00032683cfa28c4365fdcec56f531f28ceee1b72ccc00af475554ac8cfa66e4a17da4e4bee5b11390af467d8064a9bbbc6b9d939ae7cfbfa4885dd9793f0c53e96b9f9329b5a875bb1264f44df33d11639c79f6377349c957944c8df661197663a2293b0e3fa03bbd0c5f4b26bd8e0e4df3575f34dbcfec79d67a330cb0ac8832b5e9b713a1201b84607ebb2437bdf10817d78a07bc6336533e7789ffd25bc305d3dad887db29e19b1a58b220e93df8dc9ce56edaec1911820c9f493e9c515998a6b73f94a7f0652b34fab020ab06285bfc18b7a59884041e148bfbebb8be5109";
            exponent = hex"010001";
            return (modulus, exponent);
        }
    }

    uint private constant STATE_SUCCESS = 0;
    uint private constant STATE_PERMFAIL = 1;
    uint private constant STATE_TEMPFAIL = 2;

    
    struct Status {
        uint state; //验证的状态
        strings.slice message; //报错信息
    }

    struct Headers {
        uint len;
        uint signum;
        strings.slice[] name; //关键字
        strings.slice[] value; //关键字的值
        strings.slice[] signatures; //签名
    }

    struct SigTags {
        strings.slice d;    //domain签名域标识符   
        strings.slice i;    //用户标识符
        strings.slice s;    //服务类型，selector
        strings.slice b;    //正文和标题的签名
        strings.slice bh;   //正文哈希
        strings.slice cHeader;  //对于header使用的规范化算法
        strings.slice cBody;    //对于body使用的规划化算法。
        strings.slice aHash;  //使用的哈希算法
        strings.slice aKey;   //使用的秘钥类型：默认RSA
        strings.slice[] h; //可接受的哈希算法
        uint l;   //规范算法里面的制定长度
    }

    function verify(string memory raw) internal view returns (uint, string memory) {
        Headers memory headers;
        strings.slice memory body;
        string memory bodyraw;
        Status memory status;
        (headers, body, status) = parse(raw.toSlice());
        if (status.state != STATE_SUCCESS) return (0, status.message.toString());

        uint successCount = 0;
        strings.slice memory last = strings.slice(0, 0);
        for (uint i = 0; i < headers.signum; i++) {
            strings.slice memory dkimSig = headers.signatures[i];
            
            SigTags memory sigTags;
            (sigTags, status) = parseSigTags(dkimSig.copy());//继续切分signatures放到sigTags；
            if (status.state != STATE_SUCCESS) {//验证切片是否成功且完整
                if (successCount == 0) last = status.message;
                continue;
            }
            
            (status, bodyraw)= verifyBodyHash(body, sigTags);//验证内容的hash值，判断内容是否更改。
            if (status.state != STATE_SUCCESS) {
                if (successCount == 0) last = status.message;
                continue;
            }

            status = verifySignature(headers, sigTags, dkimSig);
            if (status.state != STATE_SUCCESS) {
                if (successCount == 0) last = status.message;
            } else {
                successCount++;
                last = sigTags.d;
            }
        }
        
        return (successCount, bodyraw);
    }
        function verifyBodyHash(strings.slice memory body, SigTags memory sigTags) internal pure returns (Status memory, string memory) {
        //通过body的内容算出hash与bh进行验证。
        if (sigTags.l > 0 && body._len > sigTags.l) body._len = sigTags.l;
        string memory processedBody = processBody(body, sigTags.cBody);
        bool check = false;
        if (sigTags.aHash.equals("sha256".toSlice())) {
            check = Algorithm.checkSHA256(bytes(processedBody), sigTags.bh.toString());
        } else {
            check = Algorithm.checkSHA1(bytes(processedBody), sigTags.bh.toString());
        }
        return (check ? Status(STATE_SUCCESS, strings.slice(0, 0)) : Status(STATE_PERMFAIL, "body hash did not verify".toSlice()), processedBody);
    }

    function verifySignature(Headers memory headers, SigTags memory sigTags, strings.slice memory signature) internal view returns (Status memory) {
        //通过body+header一起计算哈希与signuature进行验证。
        bytes memory modulus;
        bytes memory exponent;
        (modulus, exponent) = DKIM.getRSAKey(sigTags.d, sigTags.s);
        if (modulus.length == 0 || exponent.length == 0) {
            return Status(STATE_TEMPFAIL, "dns query error".toSlice());
        }

        bool check = false;
        string memory processedHeader = processHeader(headers, sigTags.h, sigTags.cHeader, signature);
        if (sigTags.aHash.equals("sha256".toSlice())) {
            check = Algorithm.verifyRSASHA256(modulus, exponent, bytes(processedHeader), sigTags.b.toString());
        } else {
            check = Algorithm.verifyRSASHA1(modulus, exponent, bytes(processedHeader), sigTags.b.toString());
        }
        return check ? Status(STATE_SUCCESS, strings.slice(0, 0)) : Status(STATE_PERMFAIL, "signature did not verify".toSlice());
    }

    function parse(strings.slice memory all) internal pure returns (Headers memory, strings.slice memory, Status memory) {
        //将一个大的slice进行分割切片（以冒号，换行为分割点），把标题读完后剩下的就是body，
        strings.slice memory crlf = "\r\n".toSlice();
        strings.slice memory colon = ":".toSlice();
        strings.slice memory sp = "\x20".toSlice();
        strings.slice memory tab = "\x09".toSlice();
        strings.slice memory signame = "dkim-signature".toSlice();

        Headers memory headers = Headers(0, 0, new strings.slice[](80), new strings.slice[](80), new strings.slice[](3));
        strings.slice memory headerName = strings.slice(0, 0);
        strings.slice memory headerValue = strings.slice(0, 0);
        while (!all.empty()) {
            strings.slice memory part = all.split(crlf); //一行一行的读取的all里面的内容，读到内容给part ，all的lenth和指针向后顺延
            if (part.startsWith(sp) || part.startsWith(tab)) {
                headerValue._len += crlf._len + part._len;
            } else {
                if (headerName.equals(signame)) {//读取到关键字dkim-signature，就将签名的内容放到header.signnature里面
                    headers.signatures[headers.signum] = headerValue;
                    headers.signum++;
                } else if (!headerName.empty()) {
                    headers.name[headers.len] = headerName;
                    headers.value[headers.len] = headerValue;
                    headers.len++;
                }
                headerName = toLowercase(part.copy().split(colon).toString()).toSlice();//冒号为分割，之前是name，之后为value；
                headerValue = part;
            }

            if (all.startsWith(crlf)) {//两个连续的换行符就代表读完了
                all._len -= 2;
                all._ptr += 2;
                return (headers, all, Status(STATE_SUCCESS, strings.slice(0, 0)));
            }
        }
        return (headers, all, Status(STATE_PERMFAIL, "no header boundary found".toSlice()));
    }

    // @dev https://tools.ietf.org/html/rfc6376#section-3.5
    function parseSigTags(strings.slice memory signature) internal pure returns (SigTags memory sigTags, Status memory status) {
        //将signature的内容进行切片，分类放入sigtag中，方便之后的验证。
        strings.slice memory sc = ";".toSlice();
        strings.slice memory eq = "=".toSlice();
        status = Status(STATE_SUCCESS, strings.slice(0, 0));

        signature.split(":".toSlice());
        while (!signature.empty()) {
            strings.slice memory value = signature.split(sc);
            strings.slice memory name = trim(value.split(eq));
            value = trim(value);

            if (name.equals("v".toSlice()) && !value.equals("1".toSlice())) {
                status = Status(STATE_PERMFAIL, "incompatible signature version".toSlice());
                return (sigTags, status);
            } else if (name.equals("d".toSlice())) {
                sigTags.d = value;
            } else if (name.equals("i".toSlice())) {
                sigTags.i = value;
            } else if (name.equals("s".toSlice())) {
                sigTags.s = value;
            } else if (name.equals("c".toSlice())) {
                if (value.empty()) {
                    sigTags.cHeader = "simple".toSlice();
                    sigTags.cBody = "simple".toSlice();
                } else {
                    sigTags.cHeader = value.split("/".toSlice());
                    sigTags.cBody = value;
                    if (sigTags.cBody.empty()) {
                        sigTags.cBody = "simple".toSlice();
                    }
                }
            } else if (name.equals("a".toSlice())) {
                sigTags.aKey = value.split("-".toSlice());
                sigTags.aHash = value;
                if (sigTags.aHash.empty()) {
                    status = Status(STATE_PERMFAIL, "malformed algorithm name".toSlice());
                    return (sigTags, status);
                }
                if (!sigTags.aHash.equals("sha256".toSlice()) && !sigTags.aHash.equals("sha1".toSlice())) {
                    status = Status(STATE_PERMFAIL, "unsupported hash algorithm".toSlice());
                    return (sigTags, status);
                }
                if (!sigTags.aKey.equals("rsa".toSlice())) {
                    status = Status(STATE_PERMFAIL, "unsupported key algorithm".toSlice());
                    return (sigTags, status);
                }
            } else if (name.equals("bh".toSlice())) {
                sigTags.bh = value;
            } else if (name.equals("h".toSlice())) {
                bool signedFrom;
                (sigTags.h, signedFrom) = parseSigHTag(value);
                if (!signedFrom) {
                    status = Status(STATE_PERMFAIL, "From field not signed".toSlice());
                    return (sigTags, status);
                }
            } else if (name.equals("b".toSlice())) {
                sigTags.b = unfoldContinuationLines(value, true);
            } else if (name.equals("l".toSlice())) {
                sigTags.l = stringToUint(value.toString());
            }
        }

        // The tags listed as required in Section 3.5 are v, a, b, bh, d, h, s
        if (sigTags.aKey.empty() || sigTags.b.empty() || sigTags.bh.empty() || sigTags.d.empty() || sigTags.s.empty() || sigTags.h.length == 0) {
            status = Status(STATE_PERMFAIL, "required tag missing".toSlice());
            return (sigTags, status);
        }
        if (sigTags.i.empty()) {
            // behave as though the value of i tag were "@d"                     
        } else if (!sigTags.i.endsWith(sigTags.d)) {
            status = Status(STATE_PERMFAIL, "domain mismatch".toSlice());
            return (sigTags, status);
        }
    }

    function parseSigHTag(strings.slice memory value) internal pure returns (strings.slice[] memory, bool) {
        strings.slice memory colon = ":".toSlice();
        strings.slice memory from = "from".toSlice();
        strings.slice[] memory list = new strings.slice[](value.count(colon) + 1);
        bool signedFrom = false;
  
        for(uint i = 0; i < list.length; i++) {
            strings.slice memory h = toLowercase(trim(value.split(colon)).toString()).toSlice();
            uint j = 0;
            for (; j < i; j++) if (list[j].equals(h)) break;
            if (j == i) list[i] = h;
            if (h.equals(from)) signedFrom = true;
        }
        return (list, signedFrom);
    }

    function processBody(strings.slice memory message, strings.slice memory method) internal pure returns (string memory) {
        //对body内容进行处理，去掉空格，换行，制表符。
        if (method.equals("relaxed".toSlice())) {
            message = removeSPAtEndOfLines(message);
            message = removeWSPSequences(message);
        }
        message = ignoreEmptyLineAtEnd(message);
        // https://tools.ietf.org/html/rfc6376#section-3.4.3
        if (method.equals("simple".toSlice()) && message.empty()) {
            return "\r\n";
        }
        return message.toString();
    }

    function processHeader(Headers memory headers, strings.slice[] memory tags, strings.slice memory method, strings.slice memory signature) internal pure returns (string memory) {
        //把header进行格式化处理。
        strings.slice memory crlf = "\r\n".toSlice();
        strings.slice memory colon = ":".toSlice();
        strings.slice[] memory processedHeader = new strings.slice[](tags.length + 1);
        bool isSimple = method.equals("simple".toSlice());

        for (uint j = 0; j < tags.length; j++) {
            if (tags[j].empty()) continue;
            strings.slice memory value = getHeader(headers, tags[j]);
            if (value.empty()) continue;

            if (isSimple) {
                processedHeader[j] = value;
                continue;
            }

            value.split(colon);
            value = unfoldContinuationLines(value, false);
            value = removeWSPSequences(value);
            value = trim(value);

            // Convert all header field names to lowercase
            strings.slice[] memory parts = new strings.slice[](2);
            parts[0] = tags[j];
            parts[1] = value;
            processedHeader[j] = colon.join(parts).toSlice();
        }

        if (isSimple) {
            processedHeader[processedHeader.length - 1] = signature;
        } else {
            signature.split(colon);
            // Remove signature value for "dkim-signature" header
            strings.slice memory beforeB = signature.split("b=".toSlice());
            if (signature.empty()) {
                signature = beforeB;
            } else {
                beforeB._len += 2;
                signature.split(";".toSlice());
                signature = beforeB.concat(signature).toSlice();
            }
            signature = unfoldContinuationLines(signature, false);
            signature = removeWSPSequences(signature);
            signature = trim(signature);

            processedHeader[processedHeader.length - 1] = "dkim-signature:".toSlice().concat(signature).toSlice();
        }

        return joinNoEmpty(crlf, processedHeader);
    }

    // utils
    function getHeader(Headers memory headers, strings.slice memory headerName) internal pure returns (strings.slice memory) {
      //用headername关键字例如b 、bh 等匹配找到对应的header.value
        for (uint i = 0; i < headers.len; i++) {
            if (headers.name[i].equals(headerName)) return headers.value[i].copy();
        }
        return strings.slice(0, 0);
    }

    function toLowercase(string memory str) internal pure returns (string memory) {
        //大写变小写
		bytes memory bStr = bytes(str);
		for (uint i = 0; i < bStr.length; i++) {
			if ((bStr[i] >= 0x41) && (bStr[i] <= 0x5a)) {
				bStr[i] = bytes1(uint8(bStr[i]) + 32);
			}
		}
		return string(bStr);
	}

    function tabToSp(string memory str) internal pure returns (string memory) {
        //把制表符TAB转化为空格SPace
		bytes memory bStr = bytes(str);
		for (uint i = 0; i < bStr.length; i++) {
			if (bStr[i] == 0x09) bStr[i] = 0x20;
		}
		return string(bStr);
	}

    function trim(strings.slice memory self) internal pure returns (strings.slice memory) {
        //trim：修剪 除去开头和结尾的空格、制表符、换行符
        strings.slice memory sp = "\x20".toSlice();
        strings.slice memory tab = "\x09".toSlice();
        strings.slice memory crlf = "\r\n".toSlice();
        if (self.startsWith(crlf)) {
            self._len -= 2;
            self._ptr += 2;
        }
        while (self.startsWith(sp) || self.startsWith(tab)) {
            self._len -= 1;
            self._ptr += 1;
        }
        if (self.endsWith(crlf)) {
            self._len -= 2;
        }
        while (self.endsWith(sp) || self.endsWith(tab)) {
            self._len -= 1;
        }
        return self;
    }

    function removeSPAtEndOfLines(strings.slice memory value) internal pure returns (strings.slice memory) {
        //去除末尾的空格
        if (!value.contains("\x20\r\n".toSlice())) return value;
        strings.slice memory sp = "\x20".toSlice();
        strings.slice memory crlf = "\r\n".toSlice();
        uint count = value.count(crlf);
        strings.slice[] memory parts = new strings.slice[](count + 1);
        for(uint j = 0; j < parts.length; j++) {
            parts[j] = value.split(crlf);
            while (parts[j].endsWith(sp)) {
                parts[j]._len -= 1;
            }
        }
        return crlf.join(parts).toSlice();
    }

    function removeWSPSequences(strings.slice memory value) internal pure returns (strings.slice memory) {
        //去除空格和制表符
        bool containsTab = value.contains("\x09".toSlice()); //\x09制表符
        if (!value.contains("\x20\x20".toSlice()) && !containsTab) return value;// \x20空格
        if (containsTab) value = tabToSp(value.toString()).toSlice();
        strings.slice memory sp = "\x20".toSlice();
        uint count = value.count(sp);
        strings.slice[] memory parts = new strings.slice[](count + 1);
        for(uint j = 0; j < parts.length; j++) {
            parts[j] = value.split(sp);
        }
        return joinNoEmpty(sp, parts).toSlice();
    }

    function ignoreEmptyLineAtEnd(strings.slice memory value) internal pure returns (strings.slice memory) {
        //无视最后的换行符
        strings.slice memory emptyLines = "\r\n\r\n".toSlice();
        while (value.endsWith(emptyLines)) {
            value._len -= 2;
        }
        return value;
    }

    function unfoldContinuationLines(strings.slice memory value, bool isTrim) internal pure returns (strings.slice memory) {
        //删除换行符
        strings.slice memory crlf = "\r\n".toSlice();
        uint count = value.count(crlf);//count：在value中一共包含几个crlf 具体几个赋值给count；
        if (count == 0) return value;
        strings.slice[] memory parts = new strings.slice[](count + 1);
        for(uint i = 0; i < parts.length; i++) {
            parts[i] = value.split(crlf);
            if (isTrim) parts[i] = trim(parts[i]);
        }
        return "".toSlice().join(parts).toSlice();
    }

    function stringToUint(string memory s) internal pure returns (uint result) { //字符串转化成uint
        bytes memory b = bytes(s);
        uint i;
        result = 0;
        for (i = 0; i < b.length; i++) {
            uint c = uint8(b[i]);
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
    }

    function joinNoEmpty(strings.slice memory self, strings.slice[] memory parts) internal pure returns (string memory) {
        if (parts.length == 0)
            return "";
        //将一个slice和slice数组进行拼接成一个字符串。
        uint length = 0;
        uint i;
        for(i = 0; i < parts.length; i++)
            if (parts[i]._len > 0) {
                length += self._len + parts[i]._len;
            }
        length -= self._len;

        string memory ret = new string(length);
        uint retptr;
        assembly { retptr := add(ret, 32) }

        for(i = 0; i < parts.length; i++) {
            if (parts[i]._len == 0) continue;
            memcpy(retptr, parts[i]._ptr, parts[i]._len);
            retptr += parts[i]._len;
            if (i < parts.length - 1) {
                memcpy(retptr, self._ptr, self._len);
                retptr += self._len;
            }
        }

        return ret;
    }

    function memcpy(uint dest, uint src, uint len) private pure {
        // Copy word-length chunks while possible
        //复制内存块，给一个地址和长度进行复制
        for(; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        // Copy remaining bytes
        uint mask = 256 ** (32 - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }

}

