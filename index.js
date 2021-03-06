const NodeRSA = require('node-rsa')
const sha256 = require('crypto-js/sha256')
const fs = require('fs')
const fetch = require('node-fetch')
const log = e => {
    if (e !== null)
        console.log(e)
};

['keys', 'messages'].forEach(dir => {
    if (!fs.existsSync(dir))
        fs.mkdirSync(dir, log)
})

const readOptions = {encoding: "utf-8", flag: "r"}
const writeOptions = {encoding: "utf-8", flag: "w"}

let config = {}
console.log('Generating keys...')
if (fs.existsSync("config.json")) {
    config = fs.readFileSync("config.json", readOptions)
    config = JSON.parse(config)
    const key = new NodeRSA();
    key.importKey(config.publicKey, 'pkcs8-public');
    key.importKey(config.privateKey, 'pkcs8-private');
} else {
    const key = new NodeRSA({b: 512});
    key.generateKeyPair(2048)
    config.publicKey = key.exportKey('pkcs8-public-pem')
    config.privateKey = key.exportKey('pkcs8-private-pem')
    config.name = sha256(config.publicKey).toString()
}
fs.writeFileSync("keys/"+config.name, config.publicKey, writeOptions)

console.log('Keys successful generated')

let publicKeys = fs.readdirSync("keys").map(file => {
    return {
        name: file,
        value: fs.readFileSync("keys/"+file, readOptions)
    }
})
let messages = fs.readdirSync("messages").map(file => {
    return {
        name: file,
        value: fs.readFileSync("messages/"+file, readOptions)
    }
})
let hosts = []
if (fs.existsSync("hosts.json"))
    hosts = JSON.parse(fs.readFileSync("hosts.json", readOptions))

console.log('Starting server...')
const express = require('express')
const app = express()
const args = process.argv.slice(2)
const port = args.length > 0 ? args[0] : 4444;

app.use(express.json())

app.get('/keys/public', (req, res) => {
    res.send({data: publicKeys})
})
app.post('/keys/public', (req, res) => {
    const isExists = publicKeys.find(key => key.name === req.body.name)
    if (!isExists)
        publicKeys = [...publicKeys, req.body]
    res.status(201)
    res.send({data:req.body})
})
app.get('/messages', (req, res) => {
    console.log(req.ip)
    res.send({data:messages})
})
app.post('/messages', (req, res) => {
    let host = hosts.find(h => h === req.ip)
    if (!host)
        hosts = [...hosts, req.ip]
    const toKey = new NodeRSA()
    toKey.importKey(publicKeys.find(k => k.name === req.body.to).value, 'pkcs8-public')
    const value = toKey.encrypt(req.body.body, 'base64')
    const message = {
        name: sha256(value).toString(),
        value,
    }
    messages = [...messages, message]
    hosts.filter(h => h !== req.ip || req.ip !== "127.0.0.1").forEach(host => {
        fetch('http://'+host+':'+port+'/messages/append', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(message)
        })
    })
    res.status(201)
    res.send({data:{status:"OK"}})
})
app.post('/messages/append', (req, res) => {
    console.log(req.body)
    messages = [...messages, req.body]
    res.status(201)
    res.send({data:{status:"OK"}})
})

const saveConfig = () => {
    fs.writeFileSync("config.json", JSON.stringify(config), writeOptions)
}
const savePublicKeys = () => {
    publicKeys.forEach(key => fs.writeFileSync("keys/"+key.name, key.value))
}

const saveMessages = () => {
    messages.forEach(msg => fs.writeFileSync("messages/"+msg.name, msg.value))
}
const saveHosts = () => {
    fs.writeFileSync('hosts.json', JSON.stringify(hosts), writeOptions)
}

saveConfig()

process.on("SIGINT", () => {
    savePublicKeys()
    saveMessages()
    saveConfig()
    saveHosts()

    process.exit()
})

app.listen(port, '0.0.0.0')