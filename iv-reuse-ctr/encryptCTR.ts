import {Buffer} from 'node:buffer'
import {Cipher, Decipher, createCipheriv, createDecipheriv} from 'node:crypto'

export const encryptCTR = (iv: Buffer, message: Buffer, keyEnc: Buffer): Buffer => {
    const cipher: Cipher = createCipheriv('aes-256-ctr', keyEnc, iv)

    return Buffer.concat([iv, cipher.update(message), cipher.final()])
}

export const decryptCTR = (message: Buffer, keyEnc: Buffer): Buffer => {
    const iv = message.subarray(0,16)
    const ciphertext = message.subarray(16)
    const decipher: Decipher = createDecipheriv('aes-256-ctr', keyEnc, iv)

    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}
