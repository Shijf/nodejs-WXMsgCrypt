
const crypto = require('crypto');
const errCode = require('./ErrorCode');

/**
 * 提供接收和推送给公众平台消息的加解密接口.
 */
class Prpcrypt {

    constructor(k) {
        this.key = Buffer.from(k + '=', 'base64');
        this.iv = this.key.slice(0, 16);
    }

    /**
     * 加密
     * @param {string} xmlMsg 原始需要加密的消息
     * @param {string} receiveId 
     */
    encrypt(xmlMsg, receiveId) {
        try {
            // 1. 生成随机字节流
            let random16 = crypto.pseudoRandomBytes(16);
            // 2. 将明文消息转换为 buffer
            let msg = Buffer.from(xmlMsg);
            // 3. 生成四字节的 Buffer
            let msgLength = Buffer.alloc(4);
            // 4. 生成4个字节的msg长度
            msgLength.writeUInt32BE(msg.length, 0);
            // 5. 将corpId以二进制的方式写入内存
            let corpId = Buffer.from(receiveId);
            // 6. 拼接成 buffer
            let raw_msg = Buffer.concat([random16, msgLength, msg, corpId]);
            // 7. 加密 创建加密对象
            let cipher = crypto.createCipheriv('aes-256-cbc', this.key, this.iv);
            // 8. 取消自动填充
            cipher.setAutoPadding(false);
            // 9. 使用 PKCS#7 填充
            raw_msg = this.PKCS7Encoder(raw_msg);
            let cipheredMsg = Buffer.concat([cipher.update(/*encoded*/raw_msg), cipher.final()]);
            return cipheredMsg.toString('base64');
        } catch (error) {
            throw new Error(error)
        }
    }

    /**
     * 解密
     * @param {mix} encrypted 
     * @param {number} receiveId 
     */
    decrypt(encrypted, receiveId) {

        try {
            let aesCipher = crypto.createDecipheriv("aes-256-cbc", this.key, this.iv);
            aesCipher.setAutoPadding(false); //不自动切断

            let decipheredBuff = Buffer.concat([aesCipher.update(encrypted, 'base64'), aesCipher.final()]);
            decipheredBuff = this.PKCS7Decoder(decipheredBuff);
            // 去掉rand_msg头部的16个随机字节，4个字节的msg_len, 和尾部的$CorpID即为最终的消息体原文msg
            let len_netOrder_corpid = decipheredBuff.slice(16); //去掉rand_msg头部的16个随机字节
            let msg_len = len_netOrder_corpid.slice(0, 4).readUInt32BE(0); // 4个字节的msg_len
            const result = len_netOrder_corpid.slice(4, msg_len + 4).toString();  // 最终的消息体原文msg
            let appId = len_netOrder_corpid.slice(msg_len + 4).toString(); // 尾部的$CorpID

            if (receiveId && receiveId === appId) { // 验证企业Id，不对则不通过
                return result; // 返回一个解密后的明文-
            } else {
                // return result; // 返回一个解密后的明文-
                throw Error(errCode.ValidateCorpidError);
            }
        } catch (error) {
            return new Error('errCode:' + errCode['ValidateCorpidError']);
        }
    }

    /**
     * 对需要加密的明文进行填充补位
     * @param {*} text 需要进行填充补位操作的明文
     */
    PKCS7Encoder(text) {
        const blockSize = 32;
        const textLength = text.length;
        // 计算需要填充的位数
        const amountToPad = blockSize - (textLength % blockSize);
        const result = Buffer.alloc(amountToPad);
        result.fill(amountToPad);
        return Buffer.concat([text, result]);
    }
    /**
     * 
     * 对解密后的明文进行补位删除
     * @param {string} buff 解密后的明文
     */
    PKCS7Decoder(buff) {
        var pad = buff[buff.length - 1];
        if (pad < 1 || pad > 32) {
            pad = 0;
        }
        return buff.slice(0, buff.length - pad);
    }


}
module.exports = Prpcrypt;
