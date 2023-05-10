const isDKIM = key => /^(DKIM-Signature)/.test(key);

module.exports = isDKIM;