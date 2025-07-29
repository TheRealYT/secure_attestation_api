const {verifyAttestation} = require('./index');
const {logger} = require('./logger');

const DELIMITER = '|';

const bootState = process.env.SEC_BOOT_STATE.split(DELIMITER);
const secLevel = process.env.SEC_SEC_LEVEL.split(DELIMITER);
const authTypes = process.env.SEC_AUTH_TYPES.split(DELIMITER);
const pkgNames = process.env.SEC_APP_PKG_NAMES.split(DELIMITER);
const validHashes = process.env.SEC_APP_HASHES.split(DELIMITER);

async function protect(req, res, next) {
  const challenge = req.headers['x-challenge'];
  const signature = req.headers['x-signature'];
  const certChainRaw = req.headers['x-cert-chain'];

  if (!challenge || !signature || !certChainRaw)
    return res.status(400).send('Missing attestation headers');

  const uuid = req.context = crypto.randomUUID();

  logger.info('Queue', {uuid, path: req.path, challenge, signature, certChainRaw});

  const certChain = certChainRaw.split(DELIMITER);

  await verifyAttestation(certChain, challenge, signature)
    .then(result => {
      logger.info('Valid', {uuid, ...result});

      if (
        result.deviceLocked === true &&
        bootState.includes(result.bootState) &&
        secLevel.includes(result.implSecLevel) &&
        secLevel.includes(result.storeSecLevel) &&
        authTypes.includes(result.authType) &&
        pkgNames.includes(result.packageName) &&
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