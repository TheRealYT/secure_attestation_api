const {verifyAttestation} = require('./index');
const {logger} = require('./logger');

const validHashes = process.env.APP_HASHES.split('|');

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
      logger.info('Valid', {uuid, ...result});

      if (
        result.deviceLocked === true &&
        result.bootState === 'Verified' &&
        (result.implSecLevel === 'TrustedEnvironment' || result.implSecLevel === 'StrongBox') &&
        (result.storeSecLevel === 'TrustedEnvironment' || result.storeSecLevel === 'StrongBox') &&
        result.authType === 'Fingerprint' &&
        result.packageName === process.env.APP_PKG_NAME &&
        !result.appSigns.some(s => !validHashes.includes(s))
      ) {
        return next();
      }

      res.status(403).send('Access denied!');
      return next(new Error('Device below the standard'));
    })
    .catch(err => {
      res.status(403).send('Access denied!');
      next(err);
    });
}

module.exports = {
  protect,
};