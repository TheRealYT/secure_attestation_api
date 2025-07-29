const {verifyAttestation} = require('./index');
const {logger} = require('./logger');

async function protect(req, res, next) {
  const challenge = req.headers['x-challenge'];
  const signature = req.headers['x-signature'];
  const certChainRaw = req.headers['x-cert-chain'];

  if (!challenge || !signature || !certChainRaw)
    return res.status(400).send('Missing attestation headers');

  const uuid = req.context = crypto.randomUUID();

  logger.info('Queue', {uuid, path: req.path, challenge, signature, certChainRaw});

  const certChain = certChainRaw.split('|');

  await verifyAttestation(certChain, challenge, signature)
    .then(result => {
      logger.info('Passed', {uuid, ...result});

      next();
    })
    .catch(err => {
      res.status(403).send('Access denied!');
      next(err);
    });
}

module.exports = {
  protect,
};