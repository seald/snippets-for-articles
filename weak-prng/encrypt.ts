import {Buffer} from 'node:buffer'
import {Cipher, Decipher, createCipheriv, createDecipheriv, createHmac, Hmac} from 'node:crypto'

/**
 * AES-CBC encryption with 32 bytes keys, 16 bytes IV followed by an HMAC-SHA256 with a 32 bytes key
 * with configurable PRNG for the IV.
 * Format is <IV><ciphertext><MAC>.
 */
export const encryptThenMac = (message: Buffer, keyEnc: Buffer, keyMac: Buffer, prng: (size: number) => Buffer): Buffer => {
    const iv = prng(16)
    const cipher: Cipher  = createCipheriv('aes-256-cbc', keyEnc, iv)

    const ivAndCiphertext: Buffer = Buffer.concat([iv, cipher.update(message), cipher.final()])
    const hmac: Hmac = createHmac('sha256', keyMac)
    hmac.update(ivAndCiphertext)

    return Buffer.concat([ivAndCiphertext, hmac.digest()])
}

/**
 * HMAC-SHA256 with a 32 bytes key followed by AES-CBC decryption with 32 bytes keys, 16 bytes IV
 */
export const checkMacThenDecrypt = (encryptedData: Buffer, keyEnc: Buffer, keyMac: Buffer): Buffer => {
    const ivAndCiphertext: Buffer = encryptedData.subarray(0, -32)
    const mac: Buffer = encryptedData.subarray(-32)
    const hmac: Hmac = createHmac('sha256', keyMac)
    hmac.update(ivAndCiphertext)
    const mac2 = hmac.digest()

    if (!mac.equals(mac2)) throw new Error('MAC invalid')

    const iv: Buffer = ivAndCiphertext.subarray(0,16)
    const ciphertext: Buffer = ivAndCiphertext.subarray(16)
    const decipher: Decipher  = createDecipheriv('aes-256-cbc', keyEnc, iv)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}
