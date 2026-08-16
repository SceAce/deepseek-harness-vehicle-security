import assert from 'node:assert/strict'
import test from 'node:test'
import { buildValidationPlan, classifyStrings, parseElfMetadata, parseUndefinedSymbols } from '../lib/program.js'

const header = `
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x1234
`

test('derives ELF hardening facts from readelf evidence', () => {
  const result = parseElfMetadata(
    header,
    'INTERP 0x1\nGNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x10\nGNU_RELRO 0x2',
    '(FLAGS) BIND_NOW',
    'UND __stack_chk_fail@GLIBC_2.4',
    'ELF 64-bit LSB pie executable, stripped',
  )
  assert.equal(result.machine, 'Advanced Micro Devices X86-64')
  assert.deepEqual(result.protections, {
    pie: 'enabled',
    nx: 'enabled',
    relro: 'full',
    stackCanary: 'enabled',
    stripped: 'enabled',
  })
})

test('normalizes imported symbols and removes version suffixes', () => {
  const symbols = '1: 0 0 FUNC GLOBAL DEFAULT UND system@GLIBC_2.2.5\n2: 0 0 FUNC GLOBAL DEFAULT UND socket'
  assert.deepEqual(parseUndefinedSymbols(symbols), ['socket', 'system'])
})

test('keeps negative hardening checks unknown when evidence is absent or truncated', () => {
  const result = parseElfMetadata(header, '', '', 'symbol prefix\n...[truncated 100 chars]', 'ELF 64-bit LSB executable')
  assert.equal(result.interpreter, null)
  assert.equal(result.protections.nx, 'unknown')
  assert.equal(result.protections.relro, 'unknown')
  assert.equal(result.protections.stackCanary, 'unknown')
})

test('tags only investigation-relevant strings with offsets', () => {
  const result = classifyStrings('  100 can0\n  120 password=%s\n  140 Unknown system error\n  150 ignored command line\n  160 https://ecu.local/api')
  assert.deepEqual(result, [
    { offset: '0x100', value: 'can0', tags: ['vehicle'] },
    { offset: '0x120', value: 'password=%s', tags: ['credential'] },
    { offset: '0x160', value: 'https://ecu.local/api', tags: ['network'] },
  ])
})

test('turns high-signal imports and strings into testable hypotheses', () => {
  const observations = [
    { id: 'E-004', category: 'import', statement: 'imports', source: 'readelf', details: [] },
    { id: 'E-005', category: 'string', statement: 'strings', source: 'strings', details: [] },
  ]
  const strings = [
    { offset: '0x100', value: 'password=%s', tags: ['credential'] },
    { offset: '0x200', value: 'can0', tags: ['vehicle'] },
  ]
  const result = buildValidationPlan('gateway', ['system', 'strcpy', 'socket'], strings, observations)
  assert.equal(result.hypotheses.length, 5)
  assert.deepEqual(result.hypotheses.map(item => item.id), ['H-001', 'H-002', 'H-003', 'H-004', 'H-005'])
  assert.equal(result.validationSteps[0].id, 'V-000')
  assert.match(result.hypotheses[0].title, /process-execution/)
})
