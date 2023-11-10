'use strict';
const errCode = require('./ErrorCode');
const crypto = require('crypto');
const Prpcrypt = require('./pkcs7Encoder');
const fxp = require('fast-xml-parser');
// const 

class WXBizMsgCrypt {
    /**
     * 构造函数
     * @param {string } token 开发者设置的token
     * @param {string } encodingAesKey 开发者设置的EncodingAESKey
     * @param {string } receiveId 不同应用场景传不同的id
     */
    constructor(token, encodingAesKey, receiveId) {
        this.token = token;
        this.encodingAesKey = encodingAesKey;
        this.receiveId = receiveId;
        return this;
    }
    /**
     * 验证URL
     * @param {string} sMsgSignature 签名串，对应URL参数的msg_signature
     * @param {string} sTimeStamp 时间戳，对应URL参数的timestamp
     * @param {string} sNonce 随机串，对应URL参数的nonce
     * @param {string} sEchoStr 随机串，对应URL参数的echostr
     * @param {string} sReplyEchoStr 解密之后的echostr，当return返回0时有效
     */
    VerifyURL(sMsgSignature, sTimeStamp, sNonce, sEchoStr = null) {
        if ((this.encodingAesKey).length != 43) {
            return errCode.IllegalAesKey;
        }
        //实例化加解密类
        let pc = new Prpcrypt(this.encodingAesKey);

        return pc.decrypt(sEchoStr, this.receiveId);
    }

    /**
     * 将公众平台回复用户的消息加密打包.
     * @param {string} sReplyMsg 公众平台待回复用户的消息，xml格式的字符串
     * <xml> //此处sReplyMsg的格式形式如下，其中由于回复的格式不同，MsgType有所不同
            <ToUserName><![CDATA[toUser]]></ToUserName>
            <FromUserName><![CDATA[fromUser]]></FromUserName>
            <CreateTime>1348831860</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[this is a test]]></Content>
        </xml>
     * @param {string} sTimeStamp 时间戳，可以自己生成，也可以用URL参数的timestamp
     * @param {string} sNonce 随机串，可以自己生成，也可以用URL参数的nonce
     * @param {string} sEncryptMsg 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串
     * @return {xml} 加密后的微信标准回包的json格式
     * <xml>
            <ToUserName><![CDATA[toUser]]></ToUserName>
            <FromUserName><![CDATA[fromUser]]></FromUserName>
            <CreateTime>1348831860</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[this is a test]]></Content>
        </xml>
     */
    EncryptMsg({ sReplyMsg, sTimeStamp }) {
        let pc = new Prpcrypt(this.encodingAesKey);
        // 构建微信回复的标准回包
        // <xml>
        //     <Encrypt><![CDATA[msg_encrypt]]></Encrypt>
        //     <MsgSignature><![CDATA[msg_signature]]></MsgSignature>
        //     <TimeStamp>timestamp</TimeStamp>
        //     <Nonce><![CDATA[nonce]]></Nonce>
        // </xml>
        let objStandWechatData = {
            xml: {}
        }
        let result = {
            Encrypt: {
                _cdata: null,
            },
            MsgSignature: {
                _cdata: null,
            },
            TimeStamp: null,
            Nonce: {
                _cdata: null,
            }

        };
        result.Encrypt._cdata = pc.encrypt(sReplyMsg, this.receiveId); //加密消息
        result.Nonce._cdata = parseInt((Math.random() * 100000000000), 10); //生成随机数
        result.TimeStamp = sTimeStamp || Math.floor(new Date().getTime() / 1000); //获取时间戳
        result.MsgSignature._cdata = this.GetSignature(result.TimeStamp, result.Nonce._cdata, result.Encrypt._cdata); //获得签名
        objStandWechatData.xml = result;

        //参考URL：https://www.cnblogs.com/ajanuw/p/9122228.html
        //转换为xml格式
        let XmlParser = fxp.j2xParser;
        let xmlParser = new XmlParser({
            cdataTagName: "_cdata",
        });
        let xmlResult = xmlParser.parse(objStandWechatData);
        // console.log(xmlResult);

        return xmlResult;
    }
    /**
     * 检验消息的真实性，并且获取解密后的明文.
	 * <ol>
	 *    <li>利用收到的密文生成安全签名，进行签名验证</li>
	 *    <li>若验证通过，则提取xml中的加密消息</li>
	 *    <li>对消息进行解密</li>
	 * </ol>
     * @param {string} sMsgSignature  签名串，对应URL参数的msg_signature
     * @param {string} sTimeStamp string 时间戳 对应URL参数的timestamp
     * @param {string} sNonce 随机串，对应URL参数的nonce
     * @param {string|object} sPostData 密文，对应POST请求的数据
     * @param {string} sMsg 解密后的原文
     */
    DecryptMsg(sMsgSignature, sTimeStamp, sNonce, sPostData = null) {
        try {
            //将XMl解析成对象
            if (sPostData) {
                //添加判断，在fastify版本使用fastify-xml-body-parser已经自动把post数据转化为object
                if (typeof sPostData == 'string') {
                    if (fxp.validate(sPostData)) { //optional (it'll return an object in case it's not valid)
                        console.log('XML格式出错');
                        throw new Error('XML格式出错');
                    }
                }
                let {Encrypt:EncryptMsg} = typeof sPostData == 'string'?fxp.parse(sPostData).xml:sPostData
                if (sMsgSignature !== this.GetSignature(sTimeStamp, sNonce, EncryptMsg)) {
                    throw new Error('ivalid MsgSignature');
                }
                //实例化解密函数
                let pc = new Prpcrypt(this.encodingAesKey);
                //此时返回的是明文XML，需要转换为对象
                let echoStrXml = pc.decrypt(EncryptMsg, this.receiveId);
                //进一步检验XML格式是否正确
                if (!fxp.validate(echoStrXml)) {
                    console.log('XML格式出错');
                    throw new Error('XML格式出错');
                }

                let echoStrObj = fxp.parse(echoStrXml);
                echoStrObj = echoStrObj.xml
                return echoStrObj;

            }
        } catch (error) {
            return new Error(error);
        }
    }
    /**
     * 获取签名
     */
    GetSignature(sTimeStamp, sNonce, encrypt) {
        let stringSort = [this.token, sTimeStamp, sNonce, encrypt].sort().join('');
        return this.sha1(stringSort);
    }

    sha1(str) {
        let sha1String = crypto.createHash('sha1');
        sha1String.update(str);
        let sign = sha1String.digest('hex');

        return sign;
    }

}



module.exports = WXBizMsgCrypt;