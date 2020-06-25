/*
 * @Github: https://github.com/shijf
 * @Author: shijf
 * @Date: 2020-06-25 18:58:56
 * @LastEditTime: 2020-06-25 19:38:36
 * @LastEditors: shijf
 * @FilePath: /WXMsgCrypt/example/index.js
 * @Description: 
 */
const express = require('express');
const server = express();
const bodyParser = require("body-parser");
const port = 3000;
server.use(bodyParser.urlencoded({
    extended: true
}));

// 假设你的 token 和 key 为如下的值
const config = {
    corpId: '*******', // 你的企业ID, 公众号不用,但是解密的思路一样的稍微改下代码,参见 /WXMsgCrypt/pkcs7****.js 第 69 行.
    token: '***********', // token
    aes_key: '**********Ahwyr3' // key值
}

// 引入加解密库
const WXBizMsgCrypt = require('./../index');

// 实例化加解密库

const wxBizMsgCrypt = new WXBizMsgCrypt(config.token, config.aes_key, config.corpId); // 会自动解构

server.get('/', (req, res) => {
    res.send('Hello World!')
})

// GET 请求主要用来验证 url 的，这里只演示企业微信的用法，微信公众号只需要将 明文返回即可，如果需要验证则逻辑和如下相同
server.get('/server', (req, res) => {
    /** 拿到 query 的值并解构如下
     *  msg_signature: '4b1999109ff2a628509b7edcaa460a07bb0f8675',
        timestamp: '1593083194',
        nonce: '1593678893',
        echostr: '7t5l6jS0mub7H/H+SX3sYTmHp8ONrNB9uVKcrVW38XYUIH9YovC0/AILhmtzB9KZoB3whKAM9Iw0FAz5RGU1nw=='
     */
    const { msg_signature, timestamp, nonce, echostr } = req.query;

    const replyEchostrMsg = wxBizMsgCrypt.VerifyURL(msg_signature, timestamp, nonce, echostr); // 会将密文 echostr 解密出来，在返回企业欸新即可

    res.send(replyEchostrMsg)
})

// 验证URL成功后，企业微信端会以POST的形式，将加密消息发送给我们的服务端
server.post('/server', (req, res) => {

    let data = '';//添加接收变量
    req.setEncoding('utf8');

    req.on('data', function (chunk) { //接收 数据包
        data += chunk;
    });
    req.on('end', function () { // 接受完以后
        // 解密的时候，同样需要拿到 以下 query 参数，不过此时没有了echostr
        const { msg_signature, timestamp, nonce } = req.query;
        // 将接收完的 data 数据包，进行解密
        let recivedMsg = wxBizMsgCrypt.DecryptMsg(msg_signature, timestamp, nonce, data);
        /**
         * 拿到的对象如下，为了保证通用性，并没有对原始格式进行改变，只是转为对象形式
         * 
         * {
            ToUserName: 'a****0', // 成员UserID
            FromUserName: '******', // CorpID
            CreateTime: 1593084439, // 消息创建时间（整型）
            MsgType: 'text', // 消息类型，很明显这个是文本的形式
            Content: '测试一下', // 这个就是我们回复的内容
            MsgId: 241693613, // 消息ID 可以排重
            AgentID: 1***1*5 // 是哪个应用发来的
            }
         */
        // console.log(recivedMsg);
        // res.send(data); // 可以将其原封不动返回去，因为总得返回点什么

        // 假设不论企业微信发个我们什么，我们都回复一样的，仅仅为了测试而已
        // 构建消息体
        const testXmlData = MessageHandle.textXml({
            toUser: '*****', // 员工号?或者账号就是 userid
            fromUser: config.corpId, // 此处固定为 企业CorpID
            content: '测试一下' // 我们要发送的内容
        })
        // 加密消息体
        let sendReplyMsg = wxBizMsgCrypt.EncryptMsg(testXmlData);
        
        res.send(sendReplyMsg);
    });
})

server.listen(port, () => console.log(`Example app listening on port ${port}!`))

/**
 * @description: 为了演示，我们构建一个明文的文本消息结构
 * @param {type} 
 * @return: 
 */
class MessageHandle {
    static textXml({ toUser, fromUser, content }) {
        const sTimeStamp = parseInt(new Date().valueOf() / 1000);
        return {
            sReplyMsg: `<xml><ToUserName><![CDATA[${toUser}]]></ToUserName><FromUserName><![CDATA[${fromUser}]]></FromUserName><CreateTime>${sTimeStamp}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[${content}]]></Content></xml>`,
            sTimeStamp
        }
    }
}