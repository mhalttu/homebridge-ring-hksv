import assert from 'node:assert/strict'
import { createECDH, randomBytes } from 'node:crypto'
import { createRequire } from 'node:module'
import test from 'node:test'

const require = createRequire(import.meta.url)
const requireFromRing = createRequire(require.resolve('ring-client-api'))
const requireFromReceiver = createRequire(
  requireFromRing.resolve('@eneris/push-receiver'),
)
const { default: decrypt } = requireFromReceiver('./utils/decrypt.js')
const { encrypt } = requireFromReceiver('http_ece')

test('decrypts Ring pushes with single and multi-parameter FCM headers', () => {
  const sender = createECDH('prime256v1')
  const receiver = createECDH('prime256v1')
  const senderPublicKey = sender.generateKeys('base64url')
  const receiverPublicKey = receiver.generateKeys()
  const authSecret = randomBytes(16)
  const salt = randomBytes(16)
  const payload = { event: 'motion' }
  const rawData = encrypt(Buffer.from(JSON.stringify(payload)), {
    version: 'aesgcm',
    authSecret,
    dh: receiverPublicKey,
    privateKey: sender,
    salt,
  })
  const keys = {
    privateKey: receiver.getPrivateKey('base64'),
    authSecret: authSecret.toString('base64url'),
  }
  const dh = `dh=${senderPublicKey}`
  const saltParam = `salt=${salt.toString('base64')}`
  const cases = [
    [dh, saltParam],
    [`${dh}; p256ecdsa=signature`, saltParam],
    [`p256ecdsa=signature; ${dh}`, `rs=4096; ${saltParam}`],
  ]

  for (const [cryptoKey, encryption] of cases) {
    const appData = [
      { key: 'crypto-key', value: cryptoKey },
      { key: 'encryption', value: encryption },
    ]
    assert.deepEqual(decrypt({ appData, rawData }, keys), payload, cryptoKey)
  }
})
