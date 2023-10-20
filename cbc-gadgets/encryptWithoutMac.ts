import {Buffer} from 'node:buffer'
import {Cipher, createCipheriv, createDecipheriv, createHmac, Hmac, randomBytes} from 'node:crypto'

/**
 * AES-CBC encryption with 32 bytes keys, 16 bytes IV
 * Format is <IV><ciphertext>.
 */
export const encrypt = (message: Buffer, keyEnc: Buffer): Buffer => {
    const iv = randomBytes(16)
    const cipher: Cipher = createCipheriv('aes-256-cbc', keyEnc, iv)

    return Buffer.concat([iv, cipher.update(message), cipher.final()])
}

/**
 * AES-CBC decryption with 32 bytes keys, 16 bytes IV
 */
export const decrypt = (encryptedData: Buffer, keyEnc: Buffer): Buffer => {
    const iv: Buffer = encryptedData.subarray(0, 16)
    const ciphertext: Buffer = encryptedData.subarray(16)
    const decipher: Cipher = createDecipheriv('aes-256-cbc', keyEnc, iv)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}
