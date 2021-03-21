const NodeRSA = require('node-rsa')
const fs = require('fs')

const message = process.argv[2]

const config = JSON.parse(fs.readFileSync("config.json", {encoding: "utf-8", flag: "r"}))

const key = new NodeRSA();
key.importKey(config.privateKey, "pkcs8-private")
console.log(key.decrypt(fs.readFileSync("messages/"+message, {encoding: "utf-8", flag: "r"}), "utf-8"))