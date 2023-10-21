import {Buffer} from 'node:buffer'
import {randomBytes} from 'node:crypto'
import {decryptCTR, encryptCTR} from "./encryptCTR.js";

const xor = (buf1: Buffer, buf2: Buffer): Buffer => Buffer.from(buf1.map((b, i) => b ^ buf2[i]))

// let's build two messages of exactly the same length in bytes
const message1 = Buffer.from('here is one half of the message,')
const message2 = Buffer.from('and here is the other half of it')

// let's pad them with 0 so that xor-ing them equates concatenating them
const paddedMessage1 = Buffer.concat([message1, Buffer.alloc(message2.length)])
const paddedMessage2 = Buffer.concat([Buffer.alloc(message1.length), message2])

// let's check that
if (message1.length !== message2.length) throw new Error('demo will not work, messages do not have the same length')
if (!xor(paddedMessage1, paddedMessage2).equals(Buffer.concat([message1, message2]))) throw new Error('demo will not work, padding is incorrect')

const reuseIVAndDecrypt = () => {
    // Alice is negligent and does not rotate properly the IV for a given key, and magically shares the key with Bob
    const iv = randomBytes(16)
    const key = randomBytes(32)

    const encryptedMessage1 = encryptCTR(iv, paddedMessage1, key)
    const encryptedMessage2 = encryptCTR(iv, paddedMessage2, key)

    // Bob naively decrypts the messages:
    const decryptedMessage1 = decryptCTR(encryptedMessage1, key)
    const decryptedMessage2 = decryptCTR(encryptedMessage2, key)

    console.log('Bob (m1):', decryptedMessage1.toString('utf8'))
    console.log('Bob (m2):', decryptedMessage2.toString('utf8'))

    // reusing the same iv + key outputs the same keystream in any stream cipher like AES-CTR
    // E(m1) = keyStream ^ m1
    // E(m2) = keyStream ^ m2
    // XORing the encrypted outputs gives the following:
    // E(m1) ^ E(m2)
    // = keyStream ^ m1 ^ keyStream ^ m2
    // = m1 ^ keyStream ^ keyStream ^ m2
    // = m1 ^ 0 ^ m2
    // = m1 ^ m2
    // which means that xoring the output of two encrypted messages with the same {key, iv} equates to xoring the two
    // plaintext messages
    const xorResult = xor(encryptedMessage1.subarray(16), encryptedMessage2.subarray(16))

    // In the very special case where xoring equates concatenating, there's no extra work to do
    // but in practice this makes breaking the messages nearly trivial with brute force
    if (xorResult !== Buffer.concat([message1, message2]))
    console.log('attacker (m1^m2):', xorResult.toString('utf8'))
}

reuseIVAndDecrypt()
