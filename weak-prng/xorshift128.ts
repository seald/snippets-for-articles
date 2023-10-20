import {mantissaToFloat, State} from "./break-prng.js";

/**
 * This function produces a random number out of a PRNG state as V8 does it.
 * It just shifts the state 12 bits to the right to get a 64bits integer with the mantissa,
 * converts it to a float with the default exponent to get a value between 1 and 2, and subtracts 1.
 */
export const extractNumberFromState = (state: State) => mantissaToFloat(state[0] >> 12n) - 1

/**
 * Implementation of XorShift128p in JS using BigInts
 */
export const xorShift128p = ([seState0, seState1]: State): State => {
    let s1: bigint = seState0
    let s0: bigint = seState1
    // BigInt are of arbitrary size, therefore a bitshift to the left just the bigint longer rather than truncate it. BigInt.asUintN allows to simulate a proper bitshift.
    s1 ^= BigInt.asUintN(64, s1 << 23n)
    s1 ^=  s1 >> 17n
    s1 ^= s0
    s1 ^= s0 >> 26n
    return [seState1, s1]
}

/**
 * Reverse XorShift128p, based on https://blog.securityevaluators.com/xorshift128-backward-ff3365dc0c17
 */
export const reverseXorShift128p = ([seState0, seState1]: State): State => {
    let prevState1 = seState0
    let prevState0 = seState1
    prevState0 ^= (seState0 >> 26n)
    prevState0 ^= seState0
    prevState0 ^= (prevState0 >> 17n) ^ (prevState0 >> 34n) ^ (prevState0 >> 51n)
    prevState0 ^= BigInt.asUintN(64, (prevState0 << 23n)) ^ BigInt.asUintN(64, (prevState0 << 46n))
    return [prevState0, prevState1]
}
