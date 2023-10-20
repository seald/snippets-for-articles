import {Buffer} from 'node:buffer'
import {createHmac, Hmac} from 'node:crypto'

/**
 * Calculates and appends a HMAC-SHA256 with a 32 bytes key of a payload to it
 * Format is <payload><MAC>.
 */
export const appendMac = (payload: Buffer, keyMac: Buffer): Buffer => {
    const hmac: Hmac = createHmac('sha256', keyMac)
    hmac.update(payload)
    return Buffer.concat([payload, hmac.digest()])
}

/**
 * Check HMAC-SHA256 of a payload with a 32 bytes key and returns payload
 * Warning: the check is not implemented in constant time, but this is a toy project
 */
export const checkMacThenReturnPayload = (encryptedData: Buffer, keyMac: Buffer): Buffer => {
    const payload: Buffer = encryptedData.subarray(0, -32)
    const mac: Buffer = encryptedData.subarray(-32)
    const hmac: Hmac = createHmac('sha256', keyMac)
    hmac.update(payload)
    const mac2 = hmac.digest()

    if (!mac.equals(mac2)) throw new Error('MAC invalid')

    return payload
}
