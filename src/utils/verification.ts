import { verify } from 'ripple-keypairs';
import { decode } from 'ripple-binary-codec';

/**
 * Verifies the manifest's ephemeral and master signatures.
 */
export function verifyPublisherManifest(manifestBase64: string): {
  isEphemeralValid: boolean;
  isMasterValid: boolean;
  SigningPubKey: string;
} {
  if (!manifestBase64) throw new Error('Manifest is missing');

  const manifestHex = Buffer.from(manifestBase64, 'base64').toString('hex'); // Decode the base64 manifest to hex
  const manifestObj = decode(manifestHex); // Decode hex manifest using ripple-binary-codec to get object fields

  // Validate fields
  const { Sequence, PublicKey, SigningPubKey, Signature, MasterSignature, Domain } = manifestObj;

  if (
    typeof Sequence !== 'number' ||
    typeof PublicKey !== 'string' ||
    typeof SigningPubKey !== 'string' ||
    typeof Signature !== 'string' ||
    typeof MasterSignature !== 'string'
  ) {
    throw new Error('Manifest is missing required fields or has incorrect types');
  }

  // Restore original message to check manifest's ephemeral and master signatures
  const verifyFields: Buffer[] = [Buffer.from('MAN\x00', 'utf-8')];

  // Sequence (0x24)
  const sequenceBuffer = Buffer.alloc(5);
  sequenceBuffer.writeUInt8(0x24);
  sequenceBuffer.writeUInt32BE(Sequence, 1);
  verifyFields.push(sequenceBuffer);

  // PublicKey (0x71)
  const publicKeyBytes = PublicKey.length / 2;
  const publicKeyBuffer = Buffer.alloc(2 + publicKeyBytes);
  publicKeyBuffer.writeUInt8(0x71);
  publicKeyBuffer.writeUInt8(publicKeyBytes, 1);
  publicKeyBuffer.write(PublicKey, 2, 'hex');
  verifyFields.push(publicKeyBuffer);

  // SigningPubKey (0x73)
  const signingKeyBytes = SigningPubKey.length / 2;
  const signingKeyBuffer = Buffer.alloc(2 + signingKeyBytes);
  signingKeyBuffer.writeUInt8(0x73);
  signingKeyBuffer.writeUInt8(signingKeyBytes, 1);
  signingKeyBuffer.write(SigningPubKey, 2, 'hex');
  verifyFields.push(signingKeyBuffer);

  // Optional Domain (0x77)
  if (Domain && typeof Domain === 'string') {
    const domainBytes = Domain.length / 2;
    const domainBuffer = Buffer.alloc(2 + domainBytes);
    domainBuffer.writeUInt8(0x77);
    domainBuffer.writeUInt8(domainBytes, 1);
    domainBuffer.write(Domain, 2, 'hex');
    verifyFields.push(domainBuffer);
  }

  const verifyData = Buffer.concat(verifyFields).toString('hex');

  const isEphemeralValid = verify(verifyData, Signature, SigningPubKey);
  const isMasterValid = verify(verifyData, MasterSignature, PublicKey);

  return {
    isEphemeralValid,
    isMasterValid,
    SigningPubKey
  };
}

/**
 * Verifies a signed blob using the provided public key.
 */
export function verifyBlobSignature(blobBase64: string, signature: string, publicKey: string): boolean {
  if (!blobBase64 || !signature || !publicKey) {
    throw new Error('Missing parameters for blob signature verification');
  }

  const decodedBlobHex = Buffer.from(blobBase64, 'base64').toString('hex');
  return verify(decodedBlobHex, signature, publicKey);
}
