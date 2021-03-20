const NodeRSA = require('node-rsa')
const sha256 = require('crypto-js/sha256')
const fs = require('fs')
const log = e => {
    if (e !== null)
        console.log(e)
};

['keys', 'messages'].forEach(dir => {
    if (!fs.existsSync(dir))
        fs.mkdirSync(dir, log)
})

// console.log('Generating keys...')
// const key = new NodeRSA({b: 512})
// key.generateKeyPair(2048)
// const publicKey = key.exportKey('pkcs8-public-pem')
// const privateKey = key.exportKey('pkcs8-private-pem')
// fs.writeFile("public.asc", public, log)
// fs.writeFile("private.asc", public, log)
// console.log('Keys successful generated')

let publicKeys = fs.readdirSync("keys").map(file => {
    return {
        name: file,
        value: fs.readFileSync("keys/"+file, {encoding: "utf-8", flag: "r"})
    }
})
let messages = fs.readdirSync("messages").map(file => {
    return {
        name: file,
        value: fs.readFileSync("messages/"+file, {encoding: "utf-8", flag: "r"})
    }
})

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
    res.send({data:messages})
})
app.post('/messages', (req, res) => {
    messages = [...messages, {
        name: sha256(req.body.body),
        value: req.body.body,
    }]
    res.status(201)
    res.send({data:{status:"OK"}})
})

process.on("SIGINT", () => {
    publicKeys.forEach(key => fs.writeFileSync("keys/"+key.name, key.value))
    messages.forEach(msg => fs.writeFileSync("messages/"+msg.name, msg.value))

    process.exit()
})

app.listen(port, () => {
    console.log('Server successful started at port ' + port)
},null)