const express = require('express');
const {verifyAttestation} = require('./index');

const app = express();

app.post('/protected-route', express.json(), async (req, res) => {
  const challenge = req.headers['x-challenge'];
  const signature = req.headers['x-signature'];
  const certChainRaw = req.headers['x-cert-chain'];

  if (!challenge || !signature || !certChainRaw) {
    return res.status(400).send('Missing attestation headers');
  }

  const certChain = certChainRaw.split('|');

  await verifyAttestation(certChain, challenge, signature);

  console.log('Passed!', challenge);

  res.send('Protected content accessed!');
});

app.listen(3000, () => console.log('Started'));
