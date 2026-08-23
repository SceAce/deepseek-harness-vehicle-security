import type { CtfArtifactProfile } from './artifact.js'
import { hasCapability } from './capabilities.js'
import type { CtfToolAuditResult } from './capabilities.js'
import { makeHumanRequest } from './human.js'
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
  toolGraph: CtfToolGraph
  nextActions: CtfNextAction[]
  humanRequired: CtfHumanRequest[]
}

export interface CtfToolGraph {
  category: ResolvedCtfCategory
  entry: string
  nodes: Array<{
    tool: string
    role: string
    when: string
  }>
  edges: Array<{
    from: string
    to: string
    condition: string
  }>
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
    toolGraph: toolGraphForCategory(category),
    nextActions,
    humanRequired,
  }
}

export function toolGraphForCategory(category: ResolvedCtfCategory): CtfToolGraph {
  switch (category) {
    case 're':
      return {
        category,
        entry: 'ctf_re_profile',
        nodes: [
          { tool: 'ctf_start', role: 'route and select the first path', when: 'always for a new challenge' },
          { tool: 'ctf_tool_audit', role: 'discover installed RE/runtime capabilities', when: 'capability state is unknown or stale' },
          { tool: 'ctf_artifact_profile', role: 'anchor file identity and type', when: 'a local artifact is present' },
          { tool: 'ctf_re_profile', role: 'collect imports, strings, format, and static leads', when: 'the artifact is executable or source-like' },
          { tool: 'ctf_re_r2_query', role: 'run focused radare2 analysis commands', when: 'headless disassembly, JSON metadata, or xrefs are needed' },
          { tool: 'mcp.r2', role: 'dispatch interactive or long-running radare2 MCP operations', when: 'r2 MCP is configured and the query needs stateful analysis' },
          { tool: 'ctf_re_ida_script', role: 'generate or run a focused IDAPython script', when: 'IDA-specific analysis or decompiler-side scripting is needed' },
          { tool: 'mcp.ida_pro', role: 'use the configured IDA MCP for database, decompiler, functions, and xrefs', when: 'IDA MCP is configured' },
          { tool: 'ctf_pwn_gdb_probe', role: 'observe runtime state through Pwndbg', when: 'a local debugger is available and runtime state matters' },
          { tool: 'ctf_pwn_debug_probe', role: 'observe runtime branches, registers, and memory', when: 'static evidence needs runtime confirmation' },
          { tool: 'ctf_rop_search', role: 'search gadgets', when: 'gadget-based control flow is plausible' },
          { tool: 'ctf_crypto_probe', role: 'probe encodings and constants', when: 'strings or constants suggest an encoding/crypto path' },
          { tool: 'mcp.tavily', role: 'search CVEs, vulnerable versions, and external technical references', when: 'external version or vulnerability context is required and Tavily MCP is configured' },
          { tool: 'ctf_human_request', role: 'handoff a required environment action', when: 'a person must operate a GUI, device, or service' },
        ],
        edges: [
          { from: 'ctf_start', to: 'ctf_tool_audit', condition: 'capability inventory is missing' },
          { from: 'ctf_start', to: 'ctf_artifact_profile', condition: 'path is provided' },
          { from: 'ctf_artifact_profile', to: 'ctf_re_profile', condition: 'artifact is executable or source-like' },
          { from: 'ctf_re_profile', to: 'ctf_re_r2_query', condition: 'headless reverse-engineering queries are the next highest-value action' },
          { from: 'ctf_re_profile', to: 'mcp.r2', condition: 'r2 MCP is configured and stateful analysis is more useful than a one-shot query' },
          { from: 'ctf_re_profile', to: 'ctf_re_ida_script', condition: 'IDA script or decompiler evidence is required' },
          { from: 'ctf_re_profile', to: 'mcp.ida_pro', condition: 'IDA MCP is configured and database/decompiler operations are required' },
          { from: 'ctf_re_profile', to: 'ctf_pwn_gdb_probe', condition: 'Pwndbg runtime context is available and a static hypothesis needs validation' },
          { from: 'ctf_re_profile', to: 'ctf_pwn_debug_probe', condition: 'runtime behavior must confirm a static hypothesis' },
          { from: 'ctf_re_profile', to: 'ctf_rop_search', condition: 'gadget search is relevant' },
          { from: 'ctf_re_profile', to: 'ctf_crypto_probe', condition: 'encoded constants or crypto indicators are present' },
          { from: 'ctf_re_profile', to: 'mcp.tavily', condition: 'CVE, dependency, version, or protocol reference lookup is required' },
          { from: 'ctf_re_profile', to: 'ctf_human_request', condition: 'required runtime environment is human-operated' },
        ],
      }
    case 'pwn':
      return {
        category,
        entry: 'ctf_pwn_profile',
        nodes: [
          { tool: 'ctf_start', role: 'route and select the first path', when: 'always for a new challenge' },
          { tool: 'ctf_tool_audit', role: 'discover checksec, GDB, gadget, and pwntools capabilities', when: 'capability state is unknown or stale' },
          { tool: 'ctf_artifact_profile', role: 'anchor file identity and type', when: 'a local binary is present' },
          { tool: 'ctf_pwn_profile', role: 'collect mitigations, imports, strings, and pwn leads', when: 'the artifact is an executable' },
          { tool: 'ctf_pwn_gdb_probe', role: 'collect Pwndbg context, vmmap, registers, and backtrace', when: 'Pwndbg is available or runtime state is needed' },
          { tool: 'mcp.gdb_pwndbg', role: 'dispatch interactive or stateful debugger MCP operations', when: 'GDB/Pwndbg MCP is configured' },
          { tool: 'ctf_pwn_debug_probe', role: 'collect registers, stack, maps, and branch context', when: 'runtime validation is needed' },
          { tool: 'ctf_rop_search', role: 'enumerate ROP gadgets', when: 'ROP is plausible or NX is enabled' },
          { tool: 'mcp.tavily', role: 'search libc, CVE, and version context', when: 'external vulnerability or library-version context is required and Tavily MCP is configured' },
          { tool: 'ctf_human_request', role: 'handoff service/device/GUI operation', when: 'the process or target must be started by a person' },
        ],
        edges: [
          { from: 'ctf_start', to: 'ctf_tool_audit', condition: 'capability inventory is missing' },
          { from: 'ctf_start', to: 'ctf_artifact_profile', condition: 'path is provided' },
          { from: 'ctf_artifact_profile', to: 'ctf_pwn_profile', condition: 'artifact is an executable' },
          { from: 'ctf_pwn_profile', to: 'ctf_pwn_gdb_probe', condition: 'Pwndbg runtime context is available' },
          { from: 'ctf_pwn_profile', to: 'mcp.gdb_pwndbg', condition: 'GDB/Pwndbg MCP is configured and interactive debugger state is required' },
          { from: 'ctf_pwn_profile', to: 'ctf_pwn_debug_probe', condition: 'input reachability or runtime state is unknown' },
          { from: 'ctf_pwn_profile', to: 'ctf_rop_search', condition: 'gadget-based control flow is relevant' },
          { from: 'ctf_pwn_profile', to: 'mcp.tavily', condition: 'CVE, libc, or tool-version lookup is required' },
          { from: 'ctf_pwn_profile', to: 'ctf_human_request', condition: 'target service or device is not available to tools' },
        ],
      }
    case 'web':
      return {
        category,
        entry: 'ctf_http_request',
        nodes: [
          { tool: 'ctf_start', role: 'route the challenge and detect endpoint gaps', when: 'always for a new challenge' },
          { tool: 'ctf_tool_audit', role: 'discover curl/browser/http client capabilities', when: 'capability state is unknown or stale' },
          { tool: 'ctf_http_request', role: 'capture a baseline response', when: 'a URL is available' },
          { tool: 'ctf_http_diff', role: 'compare one controlled request variation', when: 'a baseline response exists' },
          { tool: 'ctf_web_browser_probe', role: 'capture local browser DOM and screenshot state', when: 'client-side behavior or rendered DOM matters' },
          { tool: 'mcp.chrome', role: 'use the configured mcp-chrome browser bridge for tabs, DOM, console, network, cookies, and screenshots', when: 'mcp-chrome is configured' },
          { tool: 'ctf_web_capture_probe', role: 'check live mitmproxy capture and hand off startup', when: 'HTTP(S) flow capture or replay is needed' },
          { tool: 'mcp.tavily', role: 'search CVEs, framework versions, and web vulnerability references', when: 'external web research is needed and Tavily MCP is configured' },
          { tool: 'ctf_tool_setup', role: 'request mcp-chrome or mitmproxy setup', when: 'the external browser/proxy capability is not configured' },
          { tool: 'ctf_human_request', role: 'handoff service/browser/GUI operation', when: 'no endpoint or human-only interaction is available' },
        ],
        edges: [
          { from: 'ctf_start', to: 'ctf_tool_audit', condition: 'capability inventory is missing' },
          { from: 'ctf_start', to: 'ctf_http_request', condition: 'URL is provided' },
          { from: 'ctf_start', to: 'ctf_human_request', condition: 'service endpoint is missing' },
          { from: 'ctf_http_request', to: 'ctf_http_diff', condition: 'a controlled parameter or endpoint variation is ready' },
          { from: 'ctf_http_request', to: 'ctf_web_browser_probe', condition: 'rendered browser state or client-side execution must be observed' },
          { from: 'ctf_http_request', to: 'mcp.chrome', condition: 'mcp-chrome is configured and interactive browser state must be observed' },
          { from: 'ctf_http_request', to: 'ctf_web_capture_probe', condition: 'live HTTP(S) flows must be captured or replayed' },
          { from: 'ctf_http_request', to: 'mcp.tavily', condition: 'CVE, framework, dependency, or vulnerability reference lookup is required' },
          { from: 'ctf_web_browser_probe', to: 'ctf_tool_setup', condition: 'interactive mcp-chrome actions are needed' },
          { from: 'ctf_web_capture_probe', to: 'ctf_tool_setup', condition: 'mitmproxy is missing or must be configured' },
          { from: 'ctf_http_request', to: 'ctf_human_request', condition: 'browser or GUI state must be observed by a person' },
        ],
      }
    default:
      return {
        category,
        entry: 'ctf_start',
        nodes: [
          { tool: 'ctf_start', role: 'route the input', when: 'always' },
          { tool: 'ctf_tool_audit', role: 'discover local capabilities', when: 'the category or toolchain is unknown' },
          { tool: 'ctf_artifact_profile', role: 'profile a local file', when: 'a path is available' },
          { tool: 'ctf_human_request', role: 'request missing human-only input', when: 'no usable artifact or endpoint is available' },
        ],
        edges: [
          { from: 'ctf_start', to: 'ctf_tool_audit', condition: 'category is unknown' },
          { from: 'ctf_start', to: 'ctf_artifact_profile', condition: 'path is provided' },
          { from: 'ctf_start', to: 'ctf_human_request', condition: 'input is missing or human-only' },
        ],
      }
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
    return [makeHumanRequest({
      type: 'provide_data',
      title: 'Provide challenge input',
      reason: 'No artifact, URL, or challenge text was supplied.',
      operationOrder: [
        {
          order: 1,
          kind: 'instruction',
          title: 'Place or identify the challenge input',
          instruction: 'Place the challenge files in the active workspace or identify the local URL.',
          expectedSignal: 'Return a log line or OCR text containing the relative path or URL.',
        },
      ],
      acceptedReturnTypes: ['log', 'ocr_text', 'screenshot'],
      legacySteps: ['Place the challenge files in the active workspace or provide the local URL.'],
      expectedResult: {
        path: 'relative challenge file path when file-based',
        url: 'local challenge URL when web-based',
      },
      returnFields: {
        log: 'relative path or URL as text',
        ocr_text: 'recognized text containing the relative path or URL',
        screenshot: 'screenshot text or path if the input is visible in a GUI',
      },
    })]
  }
  return []
}

function startServiceRequest(input: CtfStartInput): CtfHumanRequest {
  return makeHumanRequest({
    type: 'start_service',
    title: 'Start the web challenge service',
    reason: input.path
      ? 'A web category was selected but no reachable URL was provided.'
      : 'A web category was selected and the tool layer needs a concrete host and port.',
    operationOrder: [
      {
        order: 1,
        kind: 'instruction',
        title: 'Start or locate the service',
        instruction: input.path
          ? `Start the challenge service for ${input.path}, or identify the already-running endpoint.`
          : 'Start the challenge service locally, or identify the already-running endpoint.',
        expectedSignal: 'Return terminal log text showing the listening host and port, or OCR/screenshot text with the endpoint.',
      },
      {
        order: 2,
        kind: 'command',
        title: 'Check that the service answers',
        command: 'curl -i -sS --max-time 5 http://HOST:PORT/',
        expectedSignal: 'Return curl response headers/body preview as log text, replacing HOST and PORT with the observed endpoint.',
      },
    ],
    acceptedReturnTypes: ['log', 'screenshot', 'ocr_text'],
    legacySteps: ['Start the challenge service locally or provide the already-running endpoint.', 'Keep the service running for subsequent HTTP diff tools.'],
    expectedResult: {
      scheme: 'http or https',
      host: 'hostname or IP',
      port: 'listening port',
      basePath: 'optional base path',
      cookie: 'optional baseline cookie',
    },
    returnFields: {
      log: 'service startup log, curl output, or terminal text',
      screenshot: 'screenshot text showing the endpoint or browser result',
      ocr_text: 'OCR text containing host, port, scheme, base path, cookie, or token',
    },
  })
}
