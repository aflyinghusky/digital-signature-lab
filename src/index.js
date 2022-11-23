const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());
const port = 6000;


app.get('/generate-key-pair', (req, res) => {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'der'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'der',
      }
    });

    res.send({
      publicKey: publicKey.toString('base64'),
      privateKey: privateKey.toString('base64'),
    })
  } catch (error) {
    console.log(error)
    res.send(error);
  }
})

app.post('/encrypt', (req, res) => {
  let { message, publicKey } = req.body;
  console.log(publicKey)
  const publicKeyBuffer = crypto.createPublicKey({
    key: publicKey,
    type: 'spki',
    format: 'der',
  });

  const encryptedData = crypto.publicEncrypt(
    {
      key: publicKeyBuffer,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(JSON.stringify(message)),
  );
  res.send({
    encryptedMessage: encryptedData,
    message,
    publicKey,
  });
});

app.post('/decrypt', (req, res) => {
  let { privateKey, encryptedMessage } = req.body;

  const privateKeyBuffer = crypto.createPrivateKey({
    key: Buffer.from(privateKey),
    type: 'pkcs8',
    format: 'der',
  });

  console.log('encrypted: ', encryptedData.toString('base64'));


  const decryptedMessage = crypto.privateDecrypt(
    {
      key: privateKeyBuffer,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
      passphrase: 'top secret'
    },
    encryptedData,
  );

  res.send({
    encryptedMessage,
    decryptedMessage: JSON.parse(decryptedMessage.toString()),
  });
})

app.get('/', (req, res) => {
  res.send('Hello World!')
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
});
