const SERVICES = new Map<number, string>([
  [0x10, 'DiagnosticSessionControl'],
  [0x11, 'ECUReset'],
  [0x14, 'ClearDiagnosticInformation'],
  [0x19, 'ReadDTCInformation'],
  [0x22, 'ReadDataByIdentifier'],
  [0x23, 'ReadMemoryByAddress'],
  [0x27, 'SecurityAccess'],
  [0x28, 'CommunicationControl'],
  [0x2E, 'WriteDataByIdentifier'],
  [0x2F, 'InputOutputControlByIdentifier'],
  [0x31, 'RoutineControl'],
  [0x34, 'RequestDownload'],
  [0x35, 'RequestUpload'],
  [0x36, 'TransferData'],
  [0x37, 'RequestTransferExit'],
  [0x3D, 'WriteMemoryByAddress'],
  [0x3E, 'TesterPresent'],
  [0x85, 'ControlDTCSetting'],
])

const NRC = new Map<number, string>([
  [0x10, 'generalReject'], [0x11, 'serviceNotSupported'],
  [0x12, 'subFunctionNotSupported'], [0x13, 'incorrectMessageLengthOrInvalidFormat'],
  [0x21, 'busyRepeatRequest'], [0x22, 'conditionsNotCorrect'],
  [0x24, 'requestSequenceError'], [0x31, 'requestOutOfRange'],
  [0x33, 'securityAccessDenied'], [0x35, 'invalidKey'],
  [0x36, 'exceedNumberOfAttempts'], [0x37, 'requiredTimeDelayNotExpired'],
  [0x70, 'uploadDownloadNotAccepted'], [0x71, 'transferDataSuspended'],
  [0x72, 'generalProgrammingFailure'], [0x73, 'wrongBlockSequenceCounter'],
  [0x78, 'requestCorrectlyReceivedResponsePending'],
])

interface TransportPayload {
  type: 'raw' | 'isotp-single' | 'isotp-first'
  payload: number[]
}

export interface UdsDecodeResult {
  rawHex: string
  payloadHex: string
  transport: TransportPayload['type']
  responseType: 'request' | 'positive' | 'negative'
  requestServiceId: string
  service: string
  dataHex: string
  serviceId?: string
  negativeResponseCode?: string
  negativeResponse?: string
  dataIdentifier?: string
  securityLevel?: number
  securityAccessOperation?: 'requestSeed' | 'sendKey'
  sessionType?: string
  routineControlType?: string
  routineIdentifier?: string
}

export function parseHexBytes(input: string): number[] {
  const normalized = input.replaceAll(/0x/gi, '').replaceAll(/[^0-9a-f]/gi, '')
  if (normalized.length === 0 || normalized.length % 2 !== 0) {
    throw new Error('payload must contain a non-empty, even number of hex digits')
  }
  return Array.from({ length: normalized.length / 2 }, (_, index) =>
    Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16))
}

export function decodeUds(input: string, stripIsoTp = true): UdsDecodeResult {
  const raw = parseHexBytes(input)
  const transport = stripIsoTp ? unwrapIsoTp(raw) : { type: 'raw' as const, payload: raw }
  const payload = transport.payload
  if (payload.length === 0) throw new Error('UDS payload is empty after ISO-TP decoding')

  const sid = payload[0]
  const base = {
    rawHex: toHex(raw),
    payloadHex: toHex(payload),
    transport: transport.type,
  }

  if (sid === 0x7F) {
    if (payload.length < 3) throw new Error('negative response requires SID and NRC bytes')
    return {
      ...base,
      responseType: 'negative',
      requestServiceId: hexByte(payload[1]),
      service: SERVICES.get(payload[1]) ?? 'UnknownService',
      negativeResponseCode: hexByte(payload[2]),
      negativeResponse: NRC.get(payload[2]) ?? 'unknownNrc',
      dataHex: toHex(payload.slice(3)),
    }
  }

  const positive = sid >= 0x40 && sid < 0xC0 && SERVICES.has(sid - 0x40)
  const requestSid = positive ? sid - 0x40 : sid
  const result: UdsDecodeResult = {
    ...base,
    responseType: positive ? 'positive' : 'request',
    serviceId: hexByte(sid),
    requestServiceId: hexByte(requestSid),
    service: SERVICES.get(requestSid) ?? 'UnknownService',
    dataHex: toHex(payload.slice(1)),
  }

  if ([0x22, 0x2E, 0x2F].includes(requestSid) && payload.length >= 3) {
    result.dataIdentifier = `0x${hexByte(payload[1])}${hexByte(payload[2])}`
  }
  if (requestSid === 0x27 && payload.length >= 2) {
    result.securityLevel = payload[1]
    result.securityAccessOperation = payload[1] % 2 === 1 ? 'requestSeed' : 'sendKey'
  }
  if (requestSid === 0x10 && payload.length >= 2) result.sessionType = hexByte(payload[1] & 0x7F)
  if (requestSid === 0x31 && payload.length >= 4) {
    result.routineControlType = hexByte(payload[1] & 0x7F)
    result.routineIdentifier = `0x${hexByte(payload[2])}${hexByte(payload[3])}`
  }
  return result
}

function unwrapIsoTp(bytes: number[]): TransportPayload {
  const frameType = bytes[0] >> 4
  if (frameType === 0 && bytes[0] <= 0x0F) {
    const length = bytes[0] & 0x0F
    if (length > bytes.length - 1) throw new Error('ISO-TP single-frame length exceeds payload')
    return { type: 'isotp-single', payload: bytes.slice(1, 1 + length) }
  }
  if (frameType === 1 && bytes.length >= 3) {
    return { type: 'isotp-first', payload: bytes.slice(2) }
  }
  return { type: 'raw', payload: bytes }
}

function toHex(bytes: number[]): string {
  return bytes.map(hexByte).join(' ')
}

function hexByte(value: number): string {
  return value.toString(16).toUpperCase().padStart(2, '0')
}
