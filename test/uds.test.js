import assert from 'node:assert/strict'
import test from 'node:test'
import { decodeUds, parseHexBytes } from '../lib/uds.js'

test('decodes an ISO-TP ReadDataByIdentifier request', () => {
  const result = decodeUds('03 22 F1 90')
  assert.equal(result.transport, 'isotp-single')
  assert.equal(result.service, 'ReadDataByIdentifier')
  assert.equal(result.dataIdentifier, '0xF190')
  assert.equal(result.responseType, 'request')
})

test('decodes a positive SecurityAccess seed response', () => {
  const result = decodeUds('67 01 DE AD BE EF')
  assert.equal(result.responseType, 'positive')
  assert.equal(result.service, 'SecurityAccess')
  assert.equal(result.securityAccessOperation, 'requestSeed')
  assert.equal(result.dataHex, '01 DE AD BE EF')
})

test('decodes a negative response code', () => {
  const result = decodeUds('7F 27 35')
  assert.deepEqual(
    [result.service, result.negativeResponse],
    ['SecurityAccess', 'invalidKey'],
  )
})

test('rejects malformed hex input', () => {
  assert.throws(() => parseHexBytes('1 22'), /even number/)
})
