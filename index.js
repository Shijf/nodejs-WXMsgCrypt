/*
 * @Github: https://github.com/shijf
 * @Author: shijf
 * @Date: 2020-06-25 18:56:41
 * @LastEditTime: 2020-06-25 19:14:35
 * @LastEditors: shijf
 * @FilePath: /WXMsgCrypt/index.js
 * @Description: 微信服务端消息 加解密库
 */

const WXBizMsgCrypt = require('./src/MsgCrypt/WXBizMsgCrypt');

let instance = null;

module.exports = WXBizMsgCrypt;
