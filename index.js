const {X509ChainBuilder, X509Certificate, cryptoProvider, PublicKey} = require('@peculiar/x509');
const {Crypto} = require('@peculiar/webcrypto');
const {id_ce_keyDescription, NonStandardKeyMintKeyDescription} = require('@peculiar/asn1-android');
const {AsnParser} = require('@peculiar/asn1-schema');

const webCrypto = new Crypto();
cryptoProvider.set(webCrypto);

const GOOGLE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU\nFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j\nlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y\n//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X\npXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI\nmQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB\n+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q\nuvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp\nZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7\ngLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82\nixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+\nNpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==\n-----END PUBLIC KEY-----`;

async function validateCertChain(certificates) {
  // Build the chain builder with the intermediate and root CA certificates
  const chainBuilder = new X509ChainBuilder({certificates: certificates.slice(1)});

  // Build and validate the chain
  const chain = await chainBuilder.build(certificates[0]);
  if (certificates.length !== chain.length || chain.length < 2)
    throw new Error('Invalid certificate chain');

  for (let i = 0; i < certificates.length - 1; i++) {
    const firstCert = certificates[i];
    const secondCert = certificates[i + 1];

    const valid = await validateCert(firstCert, secondCert);

    if (!valid)
      throw new Error('Invalid certificate chain');
  }
}

function validateChallenge(leafCert, challenge) {
  const attExt = leafCert.extensions.find(ext => ext.type === id_ce_keyDescription);
  if (!attExt) throw new Error('Attestation extension not found');

  const parsed = AsnParser.parse(attExt.value, NonStandardKeyMintKeyDescription);

  const challengeInCert = Buffer.from(parsed.attestationChallenge.buffer).toString();
  if (challengeInCert !== challenge)
    throw new Error('Challenge mismatch');

  return parsed;
}

function validateSecurity(parsed) {
  const hwEnforced = parsed.hardwareEnforced;

  const hardwareEnforced = {};

  hwEnforced.forEach(e => Object.assign(hardwareEnforced, e));
  if (!hardwareEnforced.rootOfTrust) throw new Error('Missing rootOfTrust');

  if (hardwareEnforced.rootOfTrust.verifiedBootState !== 0) throw new Error('Unverified boot');
  if (!hardwareEnforced.rootOfTrust.deviceLocked) throw new Error('Device not locked');

  if (hardwareEnforced.origin !== 0) throw new Error('Key not securely generated (origin mismatch)');
}

async function validateCert(cert, caCert) {
  return await cert.verify({
    publicKey: caCert.publicKey,
    signatureOnly: false,
  });
}

async function verifySignature(publicKey, payload, signature) {
  const key = await crypto.subtle.importKey('spki', publicKey, {
    name: 'ECDSA',
    namedCurve: 'P-256',
  }, false, ['verify']);

  return await crypto.subtle.verify({
    name: 'ECDSA',
    hash: {name: 'SHA-256'},
  }, key, signature, payload);
}

async function verifyAttestation(certChain, challenge, sign) {
  const certificates = certChain.map(c => new X509Certificate(Buffer.from(c, 'base64')));
  const leafCert = certificates[0];
  const lastCert = certificates.at(-1);

  await validateCertChain(certificates);

  const parsed = validateChallenge(leafCert, challenge);

  validateSecurity(parsed);

  const valid = await validateCert(lastCert, {
    publicKey: new PublicKey(GOOGLE_PUBLIC_KEY),
  });

  if (!valid)
    throw new Error('Invalid certificate chain');

  await verifySignature(leafCert.publicKey.rawData, Buffer.from(challenge), Buffer.from(sign, 'base64'));
}

module.exports = {verifyAttestation};