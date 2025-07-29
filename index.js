const {X509ChainBuilder, X509Certificate, cryptoProvider, PublicKey} = require('@peculiar/x509');
const {Crypto} = require('@peculiar/webcrypto');
const {id_ce_keyDescription, AttestationApplicationId, KeyMintKeyDescription} = require('@peculiar/asn1-android');
const {AsnParser} = require('@peculiar/asn1-schema');
const crypto = require('node:crypto');

const webCrypto = new Crypto();
cryptoProvider.set(webCrypto);

const GOOGLE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU\nFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j\nlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y\n//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X\npXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI\nmQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB\n+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q\nuvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp\nZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7\ngLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82\nixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+\nNpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==\n-----END PUBLIC KEY-----`;

const SECURITY_LEVEL = {
  0: 'Software',
  1: 'TrustedEnvironment',
  2: 'StrongBox',
};

const BOOT_STATE = {
  0: 'Verified',
  1: 'SelfSigned',
  2: 'Unverified',
  3: 'Failed',
};

const USER_AUTH_TYPE = {
  0: 'no',
  1: 'Password',
  2: 'Fingerprint',
};

// ECC
const ALGO = 3;

// ECC key
const KEY_SIZES = [256, 384, 521];

// const EC_CURVE = 1;

// sign, verify
const PURPOSE = [2, 3];

// not supported yet
const DIGESTS = {
  4: 'sha256',
  5: 'sha384',
  6: 'sha512',
};

const ORIGIN = 0;

/**
 * Extracts the first item from an array of type T.
 *
 * @template T
 * @param {T[]} detail - An array of type T.
 * @returns {T} The first item in the array.
 */
function extractDetails(detail) {
  const obj = {};

  detail.forEach(d => Object.assign(obj, d));

  return obj;
}

async function validateCert(cert, caCert) {
  return await cert.verify({
    publicKey: caCert.publicKey,
    signatureOnly: false,
  });
}

async function validateRootCert(rootCert) {
  const valid = await validateCert(rootCert, {
    publicKey: new PublicKey(GOOGLE_PUBLIC_KEY),
  });

  if (!valid)
    throw new Error('Untrusted root certificate');
}

async function validateCertChain(certs) {
  // Build the chain builder with the intermediate and root CA certificates
  const chainBuilder = new X509ChainBuilder({certificates: certs.slice(1)});

  // Build and validate the chain
  const chain = await chainBuilder.build(certs[0]);
  if (certs.length !== chain.length || chain.length < 2)
    throw new Error('Invalid certificate chain');

  for (let i = 0; i < certs.length - 1; i++) {
    const firstCert = certs[i];
    const secondCert = certs[i + 1];

    const valid = await validateCert(firstCert, secondCert);

    if (!valid)
      throw new Error('Invalid certificate chain');
  }
}

async function checkRevocation(certs) {
  // TODO: dynamic, https://android.googleapis.com/attestation/status
  const entries = {
    'entries': {
      '2c8cdddfd5e03bfc': {
        'status': 'REVOKED',
        'expires': '2020-11-13',
        'reason': 'KEY_COMPROMISE',
        'comment': 'Key stored on unsecure system',
      },
      'c8966fcb2fbb0d7a': {
        'status': 'SUSPENDED',
        'reason': 'SOFTWARE_FLAW',
        'comment': 'Bug in keystore causes this key malfunction b/555555',
      },
    },
  };

  for (const cert of certs) {
    if (cert.serialNumber in entries)
      throw new Error('Untrusted certificate.');
  }
}

async function verifySignature(publicKey, payload, signature) {
  const key = crypto.createPublicKey(publicKey);
  const verifier = crypto.createVerify('sha256');

  verifier.update(payload);

  return verifier.verify(key, signature);
}

function extractAttestationExtension(certificates) {
  for (const cert of certificates) {
    const ext = cert.extensions.find(ext => ext.type === id_ce_keyDescription);
    if (ext != null)
      return [cert, ext];
  }

  throw new Error('Attestation extension not found');
}

async function verifyAttestation(certChain, challenge, sign) {
  const certs = certChain.map(c => new X509Certificate(Buffer.from(c, 'base64')));
  const rootCert = certs.at(-1);

  await validateRootCert(rootCert);
  await validateCertChain(certs);
  await checkRevocation(certs);

  const [cert, ext] = extractAttestationExtension(certs);
  const key = AsnParser.parse(ext.value, KeyMintKeyDescription);

  if (key.attestationVersion !== 3)
    throw new Error('Unexpected attestation version');

  const challengeInCert = Buffer.from(key.attestationChallenge.buffer);
  if (!crypto.timingSafeEqual(challengeInCert, Buffer.from(challenge))
    || !await verifySignature(cert.publicKey.toString(), challenge, Buffer.from(sign, 'base64')))
    throw new Error('Challenge mismatch');

  const storeSecLevel = SECURITY_LEVEL[key.attestationSecurityLevel];
  const implSecLevel = SECURITY_LEVEL[key.keyMintSecurityLevel];

  const hardware = key.hardwareEnforced;
  if (hardware.purpose.some(p => !PURPOSE.includes(p)))
    throw new Error('Unexpected purpose');

  if (hardware.algorithm !== ALGO)
    throw new Error('Unexpected algorithm');

  if (!KEY_SIZES.includes(hardware.keySize))
    throw new Error('Unexpected key size');

  // hardware.noAuthRequired

  if (hardware.digest.some(d => !(d in DIGESTS)))
    throw new Error('Unexpected digest');

  // if (hardware.ecCurve !== EC_CURVE)
  //   throw new Error('Unexpected EC curve');

  if (hardware.origin !== ORIGIN)
    throw new Error('Unexpected origin');

  const {deviceLocked, verifiedBootState} = hardware.rootOfTrust;
  const bootState = BOOT_STATE[verifiedBootState];
  const {osVersion, osPatchLevel, vendorPatchLevel, bootPatchLevel} = hardware;

  const {activeDateTime, creationDateTime} = key.softwareEnforced;
  const attestationApplicationId = AsnParser.parse(key.softwareEnforced.attestationApplicationId, AttestationApplicationId);
  const packageInfos = extractDetails(attestationApplicationId.packageInfos);

  const packageName = Buffer.from(packageInfos.packageName).toString();
  const version = packageInfos.version;
  const appSigns = attestationApplicationId.signatureDigests.map(d => Buffer.from(d).toString('hex'));
  const authType = USER_AUTH_TYPE[hardware.userAuthType ?? 0];
}

module.exports = {verifyAttestation};