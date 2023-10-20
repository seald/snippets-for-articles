import {Buffer} from 'node:buffer'
import {createHmac, Hmac} from 'node:crypto'
import {decrypt, encrypt} from "./encryptWithoutMac.js";

/**
 * AES-CBC encryption with 32 bytes keys, 16 bytes IV followed by an HMAC-SHA256 with a 32 bytes key
 * Format is <IV><ciphertext><MAC>.
 */
export const encryptThenMac = (message: Buffer, keyEnc: Buffer, keyMac: Buffer): Buffer => {
    const ivAndCiphertext: Buffer = encrypt(message, keyEnc)
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

    return decrypt(ivAndCiphertext, keyEnc)
}
