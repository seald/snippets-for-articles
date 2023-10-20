import {Buffer} from 'node:buffer'
import {init} from 'z3-solver'
import type {BitVec, BitVecNum} from 'z3-solver'
import {floatToMantissa} from './prng.js'

export const mantissaToFloat = (mantissa: bigint) => {
    // We only know the mantissa, not the sign or the exponent, but we arbitrarily set them both to 0
    // which corresponds to how 1 is encoded: 1 = (-1)^0 * (1 + 0) * 2 ^ (1023-1023)
    // therefore:
    //   - the sign bit is 0
    //   - the exponent bits are 01111111111
    //   - the mantissa bits are only 0
    // 1 is therefore encoded as 0x3FF0000000000000n
    // see https://en.wikipedia.org/wiki/Double-precision_floating-point_format
    const floatAsBigInt = BigInt.asUintN(64, mantissa) | 0x3FF0000000000000n

    // Once we retrieve the float's bits as a bigint, we need to write it into a Buffer and cast it into a float
    // To do so, we use a Float64Array of size 1, in which we set the bytes to be the floatAsBigInt written as an Uint64
    const number = Buffer.alloc(8)
    number.writeBigUint64LE(floatAsBigInt)
    const float = new Float64Array(1)
    const bytes = new Uint8Array(float.buffer)
    bytes.set(number)

    // And then we return the first element of the Float64Array which casts the 8 bytes we set to a float
    return float[0]
}

const bitmask = BigInt.asUintN(64, (1n << 52n) - 1n)

export const bytesToFloats = (buffer: Buffer): number[] => {
    // we cannot decode truncated mantissas
    const numMantissas = Math.floor(buffer.length * 8 / 52)
    // if the buffer is too short, we need to up to 2 bytes at the end so that the last Buffer#readBigUint64LE() has its 64 bits even though we only read 52 of them
    const bufferToDecode = Buffer.concat([buffer, Buffer.alloc(Math.max(0, (numMantissas % 2 ? 1 : 2) - (buffer.length - Math.ceil(numMantissas * 52 / 8))))])
    const floats: number[] = []
    for (let mantissaIdx = 0; mantissaIdx < numMantissas; mantissaIdx++) {
        let mantissa: bigint
        if (mantissaIdx % 2 === 0) {
            // if we start on a full byte, we just have to read the 64 bits
            mantissa = bufferToDecode.subarray(mantissaIdx * 52 / 8, (mantissaIdx * 52 / 8) + 8).readBigUint64LE()
        } else {
            // if we start on a half-byte, we need to shift what we read by 4 bits to the right, then,
            mantissa = bufferToDecode.subarray(((mantissaIdx * 52) - 4) / 8, (((mantissaIdx * 52) - 4) / 8) + 8).readBigUint64LE() >> 4n
        }
        mantissa &= bitmask
        floats.push(mantissaToFloat(mantissa) - 1)
    }
    return floats
}

export declare type State = [bigint, bigint]

export const findXorShiftStates = async (numbers: number[]): Promise<State> => {
    const {Context} = await init();

    const {Solver, BitVec, interrupt} = Context('main');
    // Let us define 2 variables which represent the state.s0 and state.s1 variables from V8's Math.random function:
    // https://github.com/v8/v8/blob/847a2551feec46b5ada43e7dc42e8682c00061cc/src/numbers/math-random.cc#L63
    // The goal is to get to the state in which the generator was left after the last value was generated
    // in order to be able to produce the next one
    const targetState0 : BitVec = BitVec.const('target_state0', 64)
    const targetState1 : BitVec = BitVec.const('target_state1', 64)

    let currentState0: BitVec = targetState0
    let currentState1: BitVec = targetState1
    const solver = new Solver();

    // There is a catch, the Math.random values are actually generated in advance, put in a cache, and given back LIFO,
    // which means that if we generate consecutive Math.random values, they come from an array of consecutive
    // xorshift128p executions, but in reverse. Thus, we reverse the for loop here of the input values.
    for (let i = numbers.length - 1; i >= 0 ; i--) {
        let s1 = currentState0
        let s0 = currentState1
        currentState0 = s0
        s1 = s1.xor(s1.shl(23))
        s1 = s1.xor(s1.lshr(17))
        s1 = s1.xor(s0)
        s1 = s1.xor(s0.lshr(26))
        currentState1 = s1
        // What V8 does to produce the random number out of state0 is in ToDouble:
        // https://github.com/v8/v8/blob/a9f802859bc31e57037b7c293ce8008542ca03d8/src/base/utils/random-number-generator.h#L111
        // It produces a number out of the state0, with an exponent for a number between 1 and 2 (0x3FF), then subtracts
        // 1 to get an number between 0 and 1. We just do the same operation in reverse.
        const mantissa  = floatToMantissa(numbers[i] + 1)
        // Then we add an equation to the solver.
        solver.add(currentState0.lshr(12).eq(BitVec.val(mantissa, 64)))
    }
    // if the solver found a result
    if (await solver.check() === 'sat') {
        const model = solver.model()

        // we retrieve the values
        const state0Sol = model.get(targetState0) as BitVecNum
        const state0 = state0Sol.value()
        const state1Sol = model.get(targetState1) as BitVecNum
        const state1 = state1Sol.value()

        // then stop the solver to avoid memory leaks
        interrupt()

        // and return the found state
        return [state0, state1]
    }

    throw new Error('could not find solution')
}




