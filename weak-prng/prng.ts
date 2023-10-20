import {Buffer} from 'node:buffer'

/**
 * Extracts the 52-bits mantissa as a bigint from a number.
 */
export const floatToMantissa = (x: number): bigint => {
    const float = new Float64Array(1)
    float[0] = x
    const bigint = Buffer.from(float.buffer).readBigUInt64LE()
    return bigint & BigInt.asUintN(64, (1n << 52n) - 1n)
}

/**
 * Concatenates the 52-bits mantissas of an array of numbers into a Buffer.
 */
export const floatsToBytes = (numbers: number[]): Buffer => {
    // only the 52 bits mantissa is random in a Math.random()
    // we need to generate `numRandom` numbers to have enough bits
    const numRandom = numbers.length
    // this corresponds to `numBytesToGenerate` bytes
    const numBytesToGenerate = Math.ceil(numRandom * 52 / 8)
    // because of an internal use of `writeBigUint64LE`, we need to make sure that the last write will have at least
    // 8 bytes even though we write at most 7 bytes with it
    const bufferSize = (numRandom - 1) % 2 === 0 ? (numRandom -1) * 52 / 8 + 8 : ((numRandom -1) * 52 - 4) / 8 + 8
    // let's allocate a buffer with the necessary length, we'll truncate the leftover at the end
    const buf = Buffer.alloc(bufferSize)
    for (let i = 0; i < numRandom; i++) {
        // we add one because it allows to reach the random actually generated by V8 without a float truncation
        const rand = 1 + numbers[i]

        // let's extract the mantissa
        const mantissa = floatToMantissa(rand)

        // Let's add it to the buffer
        if (i % 2 === 0) { // odd case, easy
            // This writes 6 bytes and a half
            buf.writeBigUint64LE(mantissa, (i * 52) / 8)
        } else { // even case, tricky
            // get the last byte of the previous number
            const toWritePreviousByte = buf[(i * 52 - 4) / 8]
            // concatenate it to the mantissa, shifted of four bits
            const toWriteBigInt = BigInt(toWritePreviousByte) | (mantissa << 4n)
            // This writes 7 bytes, starting with the half-byte of the previous number
            buf.writeBigUint64LE(toWriteBigInt, (i * 52 - 4) / 8)
        }
    }
    return buf.subarray(0, numBytesToGenerate)
}

/**
 * Internal random cache to keep unused Math.random leftovers for future calls.
 */
let randomCache = Buffer.alloc(0)

/**
 * Internal function to add random to the cache.
 */
const addBytesToRandomCache = (size: number) => {
    // only the 52 bits mantissa is random in a Math.random()
    // we need to generate `numRandom` numbers to have enough bits
    const numRandom = Math.ceil(size * 8 / 52)
    const randoms = Array.from(Array(numRandom), Math.random)
    randomCache = Buffer.concat([randomCache, floatsToBytes(randoms)])
}
/**
 * Retrieve bytes from the random cache, and return them.
 */
export const weakRandomBytes = (size: number) => {
    // Check randomCache length
    const toGenerateLength = size - randomCache.length > 0 ? size - randomCache.length : 0
    addBytesToRandomCache(toGenerateLength)
    const result = randomCache.subarray(0, size)
    randomCache = randomCache.subarray(size)
    return result
}

/**
 * Feed the random cache to speed up future calls.
 */
addBytesToRandomCache(128) // feed the pool so that it can be retrieved faster later
