const express = require('express');
const {verifyAttestation} = require('./index');

const app = express();

async function protect(req, res, next) {
  const challenge = req.headers['x-challenge'];
  const signature = req.headers['x-signature'];
  const certChainRaw = req.headers['x-cert-chain'];

  if (!challenge || !signature || !certChainRaw) {
    return res.status(400).send('Missing attestation headers');
  }

  const certChain = certChainRaw.split('|');

  await verifyAttestation(certChain, challenge, signature)
    .then(next)
    .catch(err => {
      res.status(403).send('Access denied!');
      next(err);
    });
}

app.post('/protected-route', protect, (req, res) => {
  return res.send('Protected content accessed!\n Now, do your best whether using reveres-engineering or whatever, to access \n/secret-route\nOf course you will be rewarded');
});

app.post('/secret-route', protect, (req, res) => {
  return res.send(`You got the secret ${crypto.randomUUID()}!\nSubmit it to https://t.me/TheRecepientRobot`);
});

app.use((req, res) => {
  res.status(404).send('Not found');
});

app.use((err, req, res, _) => {
  console.error(err);

  if (!res.headersSent)
    res.status(500).send('Internal Error');
});

app.listen(3000, () => console.log('Started'));
