const cryptoJs = require('crypto-js');

const md5x2 = (value) => {
    return md5(md5(value));
};

const md5 = (value) => {
    return md5Utf8(value);
};

const md5Utf8 = (value) => {
    return cryptoJs.MD5(cryptoJs.enc.Utf8.parse(value)).toString();
};

const decrypt = (value, publicKey, privateKey) => {
    try {
        return cryptoJs.enc.Utf8.stringify(
            cryptoJs.AES.decrypt(value, md5Utf8(publicKey), {
                iv: md5Utf8(privateKey),
                mode: cryptoJs.mode.CBC,
                padding: cryptoJs.pad.Pkcs7
            })
        )
    } catch (error) {
        return null;
    }
};

const encrypt = (value, publicKey, privateKey) => {
    return cryptoJs.AES.encrypt(
        cryptoJs.enc.Utf8.parse(value),
        md5Utf8(publicKey),
        {
            iv: md5Utf8(privateKey),
            mode: cryptoJs.mode.CBC,
            padding: cryptoJs.pad.Pkcs7
        }
    ).toString();
};

module.exports = {
    md5x2,
    md5,
    decrypt,
    encrypt,
};
