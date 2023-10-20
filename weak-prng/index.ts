import {Buffer} from 'node:buffer'
import {floatsToBytes, weakRandomBytes} from './prng.js'
import {findXorShiftStates, bytesToFloats, State} from './break-prng.js'
import {encryptThenMac, checkMacThenDecrypt} from './encrypt.js'
import {xorShift128p, extractNumberFromState} from './xorshift128.js'

/**
 * Generate keys with the weakRandomBytes, encrypts 2 messages with them, and returns the encrypted messages.
 */
const generateKeysAndEncrypt = () => {
    const keyEnc: Buffer = weakRandomBytes(32)
    const keyMAC: Buffer = weakRandomBytes(32)

    const message1: Buffer = Buffer.from('Your password is:Se@ld-i5-great', 'utf8')
    const message2: Buffer = Buffer.from('This PRNG works! Amazing, no need to make a fuss around CSPRNG', 'utf8')

    const encryptedMessage1 = encryptThenMac(message1, keyEnc, keyMAC, weakRandomBytes)
    const encryptedMessage2 = encryptThenMac(message2, keyEnc, keyMAC, weakRandomBytes)
    console.log('encryptedMessage1', encryptedMessage1.toString('hex'))
    console.log('encryptedMessage2', encryptedMessage2.toString('hex'))

    return {encryptedMessage1, encryptedMessage2}
}

/**
 * Takes two encrypted messages, breaks the key generated from weakRandomBytes, and decrypts the messages.
 */
const breakKeyFromMessageIVsAndDecrypt = async ({encryptedMessage1, encryptedMessage2}) => {
    const iv1 = encryptedMessage1.subarray(0,16)
    const iv2 = encryptedMessage2.subarray(0,16)

    // iv1 and iv2 are generated after 64 bytes have been generated
    // to generate 64 bytes with 52-bits integers, we need 10 "whole" numbers (520bits = 65 bytes), which produces 65 bytes of random
    // therefore the 66th byte is the first next "whole" number
    // which corresponds to the second byte of iv1, thus we need to remove the first byte
    const bytes = Buffer.concat([iv1, iv2]).subarray(1)

    // we get back 4 numbers
    const numbers = bytesToFloats(bytes)
    // from those 4 numbers, we retrieve the PRNG state after 14 calls to Math.random
    let state: State = await findXorShiftStates(numbers)

    // we xorshift 14 times to roll back the PRNG
    const previousNumbers = []
    for (let i = 0; i< 14; i++) {
        state = xorShift128p(state)
        previousNumbers.unshift(extractNumberFromState(state))
    }

    // we generate the 64 bytes of "random" from this stream of numbers
    const predictedRandom = floatsToBytes(previousNumbers).subarray(0, 64)

    // we split the keys like the initial script
    const keyEnc: Buffer = predictedRandom.subarray(0, 32)
    const keyMAC: Buffer = predictedRandom.subarray(32, 64)

    // we decrypt
    console.log('message1:', checkMacThenDecrypt(encryptedMessage1, keyEnc, keyMAC).toString('utf8'))
    console.log('message2:', checkMacThenDecrypt(encryptedMessage2, keyEnc, keyMAC).toString('utf8'))
}

breakKeyFromMessageIVsAndDecrypt(generateKeysAndEncrypt())
    .then(() => process.exit(0), () => process.exit(1))
