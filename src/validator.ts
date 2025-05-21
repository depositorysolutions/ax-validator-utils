import path from 'path'
import * as fs from 'fs'
import { promises as fsPromises } from 'fs'
import { encodeBlob, readJson, readTxt } from './utils'
import * as Crypto from 'crypto'
import { encodeNodePublic } from 'xrpl'
import { codec, decodeNodePublic } from 'ripple-address-codec'
import { encode } from 'ripple-binary-codec'
import { sign as _sign, generateSeed, deriveKeypair } from 'ripple-keypairs'

export interface KeystoreInterface {
  domain?: string // "domain"
  key_type: string // "ed25519"
  manifest?: string // "manifest"
  public_key: string // node public key
  revoked: boolean // revoked
  secret_key: string // base58 encoded private key
  token_sequence: number // token_sequence
}
export interface ManifestInterface {
  Sequence: number
  PublicKey: string
  SigningPubKey: string
  Domain?: string
  SigningPrivateKey: string
  MasterPrivateKey: string
}

export interface ManifestResponse {
  base64: string
  xrpl: string
}

const DER_PRIVATE_KEY_PREFIX = Buffer.from(
  '302E020100300506032B657004220420',
  'hex'
)
const DER_PUBLIC_KEY_PREFIX = Buffer.from('302A300506032B6570032100', 'hex')
const VALIDATOR_HEX_PREFIX_ED25519 = 'ED'
// const VALIDATOR_NODE_PUBLIC_KEY_PREFIX = 'n'

export function generateKeystore(): KeystoreInterface {
  const keypair = Crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { format: 'der', type: 'pkcs8' },
    publicKeyEncoding: { format: 'der', type: 'spki' },
  })

  const { privateKey, publicKey } = keypair

  const PublicKey =
    VALIDATOR_HEX_PREFIX_ED25519 +
    publicKey
      .slice(DER_PUBLIC_KEY_PREFIX.length, publicKey.length)
      .toString('hex')
      .toUpperCase()

  const secretKey = codec.encode(
    privateKey.slice(DER_PRIVATE_KEY_PREFIX.length, privateKey.length),
    {
      versions: [0x20],
      expectedLength: 32,
    }
  )

  return {
    key_type: 'ed25519',
    secret_key: secretKey,
    public_key: encodeNodePublic(Buffer.from(PublicKey, 'hex')),
    revoked: false,
    token_sequence: 0,
  }
}

export function generateManifest(
  manifest: ManifestInterface
): ManifestResponse {
  const verifyFields = [Buffer.from('MAN\x00', 'utf-8')]

  // Sequence (soeREQUIRED)
  const sequenceBuffer = Buffer.alloc(5)
  sequenceBuffer.writeUInt8(0x24)
  sequenceBuffer.writeUInt32BE(manifest.Sequence, 1)
  verifyFields.push(sequenceBuffer)

  // PublicKey (soeREQUIRED)
  const publicKeyBuffer = Buffer.alloc(35)
  publicKeyBuffer.writeUInt8(0x71)
  publicKeyBuffer.writeUInt8(manifest.PublicKey.length / 2, 1)
  publicKeyBuffer.write(manifest.PublicKey, 2, 'hex')
  verifyFields.push(publicKeyBuffer)

  // SigningPubKey (soeOPTIONAL)
  const signingPubKeyBuffer = Buffer.alloc(35)
  signingPubKeyBuffer.writeUInt8(0x73)
  signingPubKeyBuffer.writeUInt8(manifest.SigningPubKey.length / 2, 1)
  signingPubKeyBuffer.write(manifest.SigningPubKey, 2, 'hex')
  verifyFields.push(signingPubKeyBuffer)

  // Domain (soeOPTIONAL)
  if (manifest.Domain) {
    const domainBuffer = Buffer.alloc(2 + manifest.Domain.length / 2) // eslint-disable-line no-mixed-operators
    domainBuffer.writeUInt8(0x77)
    domainBuffer.writeUInt8(manifest.Domain.length / 2, 1)
    domainBuffer.write(manifest.Domain, 2, 'hex')
    verifyFields.push(domainBuffer)
  }

  const verifyData = Buffer.concat(verifyFields)

  // Signature (soeOPTIONAL)
  const ephemeralSignature = sign(verifyData, manifest.SigningPrivateKey)

  // MasterSignature (soeREQUIRED)
  const masterSignature = sign(verifyData, manifest.MasterPrivateKey)

  const manifestBuffer = Buffer.from(
    encode({
      Sequence: manifest.Sequence,
      PublicKey: manifest.PublicKey,
      SigningPubKey: manifest.SigningPubKey,
      Signature: ephemeralSignature,
      Domain: manifest.Domain,
      MasterSignature: masterSignature,
    }),
    'hex'
  )
  return {
    base64: manifestBuffer.toString('base64'),
    xrpl: manifestBuffer.toString('hex').toUpperCase(),
  } as ManifestResponse
}

export function sign(message: Buffer | string, secret: string): string {
  if (typeof message === 'string') {
    message = Buffer.from(message, 'utf8') // eslint-disable-line no-param-reassign
  }

  try {
    const decoded = codec.decode(secret, { versions: [0x20] })
    secret = VALIDATOR_HEX_PREFIX_ED25519 + decoded.bytes.toString('hex') // eslint-disable-line no-param-reassign
  } catch (err) {
    // ignore
  }

  return _sign(message.toString('hex'), secret).toUpperCase()
}

export class ValidatorClient {
  name = '' // node1 | node2 | signer
  keystorePath = ''
  keyPath = ''

  constructor(name: string) {
    this.name = name
    this.keystorePath = path.join(process.cwd(), `keystore`)
    this.keyPath = path.join(this.keystorePath, `${this.name}/key.json`)
    if (!fs.existsSync(this.keystorePath)) {
      fs.mkdirSync(this.keystorePath, { recursive: true })
    }
  }

  getKeys(): any {
    try {
      return readJson(this.keyPath)
    } catch (e) {
      // console.log(e)
      return null
    }
  }

  async createKeys(): Promise<void> {
    const keyPathDir = path.join(this.keystorePath, this.name)
    if (!fs.existsSync(keyPathDir)) {
      await fsPromises.mkdir(keyPathDir, { recursive: true })
    }
    await fsPromises.writeFile(
      this.keyPath,
      JSON.stringify(generateKeystore(), null, 2)
    )
  }

  async setDomain(domain: string): Promise<void> {
    const keys = { ...this.getKeys() }
    keys.domain = domain
    keys.token_sequence += 1
    const attestation = sign(
      `[domain-attestation-blob:${keys.domain}:${keys.public_key}]`,
      keys.secret_key
    )
    const namePath = path.join(this.keystorePath, this.name)
    await fsPromises.writeFile(`${namePath}/attestation.txt`, attestation)
    await fsPromises.writeFile(this.keyPath, JSON.stringify(keys, null, 2))
  }

  async createToken(): Promise<void> {
    const keys = { ...this.getKeys() }
    const seed = generateSeed()
    const keypair = deriveKeypair(seed)
    keys.token_sequence += 1
    const manifest = generateManifest({
      Sequence: keys.token_sequence,
      Domain: keys.domain,
      PublicKey: decodeNodePublic(keys.public_key)
        .toString('hex')
        .toUpperCase(),
      SigningPubKey: keypair.publicKey,
      SigningPrivateKey: keypair.privateKey,
      MasterPrivateKey: keys.secret_key,
    })
    keys.manifest = manifest.xrpl

    const token = encodeBlob({
      validation_secret_key: keypair.privateKey.slice(2),
      manifest: manifest.base64,
    })
    const formattedToken = token.match(/.{1,72}/g)?.join('\n') ?? token

    const namePath = path.join(this.keystorePath, this.name)
    await fsPromises.writeFile(`${namePath}/manifest.txt`, manifest.base64)
    await fsPromises.writeFile(`${namePath}/token.txt`, formattedToken)
    await fsPromises.writeFile(this.keyPath, JSON.stringify(keys, null, 2))
  }

  readToken(): string {
    const tokenPath = path.join(this.keystorePath, `${this.name}/token.txt`)
    const manifest = readTxt(tokenPath)
    return manifest[0]
  }

  readManifest(): string {
    const manifestPath = path.join(
      this.keystorePath,
      `${this.name}/manifest.txt`
    )
    const manifest = readTxt(manifestPath)
    return manifest[0]
  }
}
