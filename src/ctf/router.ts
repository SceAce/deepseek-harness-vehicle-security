import type { CtfArtifactProfile } from './artifact.js'
import { hasCapability } from './capabilities.js'
import type { CtfToolAuditResult } from './capabilities.js'
import type { CtfCategory, CtfHumanRequest, CtfNextAction, ResolvedCtfCategory } from './types.js'

export interface CtfStartInput {
  objective?: string
  category?: CtfCategory
  path?: string
  url?: string
  context?: string
}

export interface CtfRouteDecision {
  category: ResolvedCtfCategory
  reasons: string[]
  recommendedTool: string
  recommendedArgs: Record<string, unknown>
  nextActions: CtfNextAction[]
  humanRequired: CtfHumanRequest[]
}

const CATEGORY_KEYWORDS: Record<Exclude<ResolvedCtfCategory, 'unknown'>, RegExp> = {
  re: /\bre\b|reverse|reversing|逆向|反编译|算法|serial|license|crackme|keygen|vm|obfusc/i,
  pwn: /\bpwn\b|overflow|rop|ret2|heap|libc|canary|format string|shellcode|栈|堆|溢出/i,
  crypto: /crypto|rsa|aes|xor|lattice|hash|md5|sha|ecc|oracle|密码|加密|解密|格|同余|因数/i,
  misc: /misc|pcap|stego|forensics|zip|png|jpg|wav|qr|barcode|流量|取证|隐写|压缩包/i,
  web: /\bweb\b|http|https|url|cookie|jwt|xss|sqli|ssti|csrf|upload|接口|网站|注入/i,
}

export function routeCtfStart(
  input: CtfStartInput,
  artifact: CtfArtifactProfile | null,
  audit: CtfToolAuditResult,
): CtfRouteDecision {
  const explicit = input.category && input.category !== 'auto' ? input.category : undefined
  const text = `${input.objective ?? ''}\n${input.context ?? ''}\n${input.url ?? ''}`
  const category = explicit ?? inferCategory(text, artifact, input.url)
  const reasons = routeReasons(category, text, artifact, Boolean(input.url), explicit)
  const { tool, args } = firstTool(category, input, artifact, audit)
  const nextActions: CtfNextAction[] = tool ? [{ tool, args, reason: reasons[0] ?? 'Run the first category-specific CTF tool.' }] : []
  const humanRequired = humanRequests(input, category)
  return {
    category,
    reasons,
    recommendedTool: tool,
    recommendedArgs: args,
    nextActions,
    humanRequired,
  }
}

function inferCategory(
  text: string,
  artifact: CtfArtifactProfile | null,
  url: string | undefined,
): ResolvedCtfCategory {
  if (url) return 'web'
  for (const [category, regex] of Object.entries(CATEGORY_KEYWORDS) as Array<[Exclude<ResolvedCtfCategory, 'unknown'>, RegExp]>) {
    if (regex.test(text)) return category
  }

  if (artifact) {
    const extension = artifact.extension
    const fileType = artifact.fileType ?? ''
    if (/\bELF\b|PE32|Mach-O|executable|shared object/i.test(fileType)) return 'pwn'
    if (['.elf', '.so', '.exe', '.dll', '.dylib'].includes(extension)) return 'pwn'
    if (['.pcap', '.pcapng', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.wav', '.mp3', '.zip', '.rar', '.7z', '.tar', '.gz'].includes(extension)) return 'misc'
    if (['.py', '.js', '.java', '.c', '.cpp', '.go', '.rs', '.txt'].includes(extension) && /encrypt|decrypt|rsa|xor|flag|cipher/i.test(artifact.textSample ?? '')) return 'crypto'
  }
  return 'unknown'
}

function routeReasons(
  category: ResolvedCtfCategory,
  text: string,
  artifact: CtfArtifactProfile | null,
  hasUrl: boolean,
  explicit: CtfCategory | undefined,
): string[] {
  const reasons: string[] = []
  if (explicit) reasons.push(`category was explicitly set to ${explicit}`)
  if (hasUrl) reasons.push('url was provided, so web tooling is the first path')
  if (artifact?.fileType) reasons.push(`artifact fileType suggests ${category}: ${artifact.fileType}`)
  if (artifact?.extension) reasons.push(`artifact extension is ${artifact.extension}`)
  for (const [candidate, regex] of Object.entries(CATEGORY_KEYWORDS)) {
    if (regex.test(text)) reasons.push(`prompt contains ${candidate} indicators`)
  }
  if (reasons.length === 0) reasons.push('no strong type signal; start with artifact profiling and tool audit')
  return reasons
}

function firstTool(
  category: ResolvedCtfCategory,
  input: CtfStartInput,
  artifact: CtfArtifactProfile | null,
  audit: CtfToolAuditResult,
): { tool: string; args: Record<string, unknown> } {
  switch (category) {
    case 'pwn':
      return artifact
        ? { tool: 'ctf_pwn_profile', args: { path: artifact.path } }
        : { tool: 'ctf_artifact_profile', args: { path: input.path } }
    case 're':
      return artifact
        ? { tool: 'ctf_re_profile', args: { path: artifact.path } }
        : { tool: 'ctf_artifact_profile', args: { path: input.path } }
    case 'web':
      return input.url
        ? { tool: 'ctf_http_request', args: { url: input.url, method: 'GET' } }
        : { tool: 'ctf_human_request', args: { request: startServiceRequest(input) } }
    case 'misc':
      return artifact
        ? { tool: /pcap/i.test(artifact.fileType ?? '') || ['.pcap', '.pcapng'].includes(artifact.extension) ? 'ctf_pcap_profile' : 'ctf_misc_triage', args: { path: artifact.path } }
        : { tool: 'ctf_artifact_profile', args: { path: input.path } }
    case 'crypto':
      return artifact
        ? { tool: 'ctf_crypto_probe', args: { path: artifact.path } }
        : { tool: 'ctf_crypto_probe', args: { text: input.context ?? input.objective ?? '' } }
    default:
      if (artifact) return { tool: 'ctf_artifact_profile', args: { path: artifact.path } }
      if (hasCapability(audit, 'web.curl') && input.url) return { tool: 'ctf_http_request', args: { url: input.url, method: 'GET' } }
      return { tool: 'ctf_tool_audit', args: {} }
  }
}

function humanRequests(input: CtfStartInput, category: ResolvedCtfCategory): CtfHumanRequest[] {
  if (category === 'web' && !input.url) return [startServiceRequest(input)]
  if (!input.path && !input.url && !(input.context ?? input.objective)?.trim()) {
    return [{
      type: 'provide_data',
      title: 'Provide challenge input',
      reason: 'No artifact, URL, or challenge text was supplied.',
      steps: [
        'Place the challenge files in the active workspace or provide the local URL.',
        'Return the relative path or URL.',
      ],
      expectedResult: {
        path: 'relative challenge file path when file-based',
        url: 'local challenge URL when web-based',
      },
    }]
  }
  return []
}

function startServiceRequest(input: CtfStartInput): CtfHumanRequest {
  return {
    type: 'start_service',
    title: 'Start the web challenge service',
    reason: input.path
      ? 'A web category was selected but no reachable URL was provided.'
      : 'A web category was selected and the tool layer needs a concrete host and port.',
    steps: [
      'Start the challenge service locally or provide the already-running endpoint.',
      'Keep the service running for subsequent HTTP diff tools.',
      'Return host, port, scheme, and any required baseline cookie or token.',
    ],
    expectedResult: {
      scheme: 'http or https',
      host: 'hostname or IP',
      port: 'listening port',
      basePath: 'optional base path',
      cookie: 'optional baseline cookie',
    },
  }
}
