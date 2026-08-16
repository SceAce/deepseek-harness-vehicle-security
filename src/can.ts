type CanFormat = 'candump' | 'asc'
type CanDirection = 'Rx' | 'Tx' | null

export interface ParsedCanFrame {
  format: CanFormat
  timestamp: number | null
  channel: string
  id: string
  direction: CanDirection
  dlc: number
  dataHex: string
}

export interface CanLogOptions {
  maxFrames?: number
  idFilter?: string
}

export interface CanLogSummary {
  format: CanFormat | 'unknown'
  totalLines: number
  parsedFrames: number
  uniqueIds: number
  firstTimestamp: number | null
  lastTimestamp: number | null
  topIds: Array<{ id: string; count: number; channels: string[] }>
  sampleFrames: Array<Omit<ParsedCanFrame, 'format'>>
}

export function parseCanLog(text: string, options: CanLogOptions = {}): CanLogSummary {
  const maxFrames = normalizeMaxFrames(options.maxFrames)
  const filters = parseIdFilter(options.idFilter)
  const frames: ParsedCanFrame[] = []
  let detectedFormat: CanLogSummary['format'] = 'unknown'

  const lines = text.split(/\r?\n/)
  for (const line of lines) {
    const parsed = parseCandumpCompact(line) ?? parseCandumpColumns(line) ?? parseAsc(line)
    if (!parsed) continue
    if (filters.size > 0 && !filters.has(parsed.id)) continue
    if (detectedFormat === 'unknown') detectedFormat = parsed.format
    if (frames.length < maxFrames) frames.push(parsed)
  }

  const counts = new Map<string, { id: string; count: number; channels: Set<string> }>()
  for (const currentFrame of frames) {
    const entry = counts.get(currentFrame.id) ?? {
      id: currentFrame.id,
      count: 0,
      channels: new Set<string>(),
    }
    entry.count += 1
    entry.channels.add(currentFrame.channel)
    counts.set(currentFrame.id, entry)
  }

  const topIds = [...counts.values()]
    .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
    .map(entry => ({ id: entry.id, count: entry.count, channels: [...entry.channels].sort() }))

  return {
    format: detectedFormat,
    totalLines: lines.length,
    parsedFrames: frames.length,
    uniqueIds: counts.size,
    firstTimestamp: frames[0]?.timestamp ?? null,
    lastTimestamp: frames.at(-1)?.timestamp ?? null,
    topIds,
    sampleFrames: frames.slice(0, 20).map(({ format: _format, ...currentFrame }) => currentFrame),
  }
}

function parseCandumpCompact(line: string): ParsedCanFrame | null {
  const match = line.match(/^\s*\((\d+(?:\.\d+)?)\)\s+(\S+)\s+([0-9A-Fa-f]{3,8})(##?)([0-9A-Fa-f]*)/)
  if (!match) return null
  let data = match[5]
  if (match[4] === '##' && data.length > 0) data = data.slice(1)
  return frame('candump', match[1], match[2], match[3], data)
}

function parseCandumpColumns(line: string): ParsedCanFrame | null {
  const match = line.match(/^\s*(?:\((\d+(?:\.\d+)?)\)\s+)?(\S+)\s+([0-9A-Fa-f]{3,8})\s+\[(\d+)]\s*((?:[0-9A-Fa-f]{2}\s*)*)/)
  if (!match) return null
  return frame('candump', match[1] ?? null, match[2], match[3], match[5])
}

function parseAsc(line: string): ParsedCanFrame | null {
  const match = line.match(/^\s*(\d+(?:\.\d+)?)\s+(\d+)\s+([0-9A-Fa-f]+)x?\s+(Rx|Tx)\s+d\s+\d+\s*((?:[0-9A-Fa-f]{2}\s*)*)/i)
  if (!match) return null
  return frame('asc', match[1], match[2], match[3], match[5], match[4] as 'Rx' | 'Tx')
}

function frame(
  format: CanFormat,
  timestamp: string | null,
  channel: string,
  id: string,
  data: string,
  direction: CanDirection = null,
): ParsedCanFrame {
  const normalizedData = data.replaceAll(/\s+/g, '').toUpperCase()
  return {
    format,
    timestamp: timestamp === null ? null : Number(timestamp),
    channel,
    id: normalizeId(id),
    direction,
    dlc: normalizedData.length / 2,
    dataHex: normalizedData.match(/.{1,2}/g)?.join(' ') ?? '',
  }
}

function parseIdFilter(value?: string): Set<string> {
  if (!value) return new Set()
  return new Set(value.split(',').map(part => normalizeId(part.trim())))
}

function normalizeId(value: string): string {
  const cleaned = value.replace(/^0x/i, '')
  if (!/^[0-9a-f]+$/i.test(cleaned)) throw new Error(`invalid CAN ID: ${value}`)
  return `0x${Number.parseInt(cleaned, 16).toString(16).toUpperCase()}`
}

function normalizeMaxFrames(value?: number): number {
  if (value === undefined) return 100_000
  if (!Number.isInteger(value) || value < 1 || value > 1_000_000) {
    throw new Error('maxFrames must be an integer between 1 and 1000000')
  }
  return value
}
