import { verifyPublisherManifest, verifyBlobSignature } from './src/utils/verification';

// Get arguments from command line: blob, manifest, publicKey, signature
const [blob, manifestBase64, signature, publicKey] = process.argv.slice(2);

if (!blob || !manifestBase64 || !signature || !publicKey) {
  console.error('Usage: ts-node run-verify.ts <blob> <manifest> <signature> <publicKey>');
  process.exit(1);
}

try {
  const { isEphemeralValid, isMasterValid, SigningPubKey } = verifyPublisherManifest(manifestBase64);

  console.log('Master Signature Valid:', isMasterValid);
  console.log('Ephemeral Signature Valid:', isEphemeralValid);

  if (!isEphemeralValid || !isMasterValid) {
    throw new Error(
      'Manifest verification failed: ' +
      (!isEphemeralValid ? 'Ephemeral signature invalid. ' : '') +
      (!isMasterValid ? 'Master signature invalid.' : '')
    );
  }

  const blobValid = verifyBlobSignature(blob, signature, SigningPubKey);
  console.log('Blob Signature Valid:', blobValid);

  if (!blobValid) {
    throw new Error('Blob signature verification failed');
  }

} catch (err) {
  console.error('Verification error:', (err as Error).message);
  process.exit(1);
}