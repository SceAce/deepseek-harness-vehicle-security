import { profileCtfArtifact, type CtfArtifactProfile } from './artifact.js'
import { makeHumanRequest } from './human.js'
import { findCtfExecutable } from './environment.js'
import type { ResolvedWorkspaceFile } from '../paths.js'
import { runCommand, type CommandOptions } from '../process.js'
import { commandRecord, emptyResult, type CtfToolResultBase } from './types.js'

export interface MiscTriageResult extends CtfToolResultBase {
  artifact: CtfArtifactProfile
  toolOutputs: Record<string, string | null>
}

export async function triageMiscArtifact(
  file: ResolvedWorkspaceFile,
  options: CommandOptions = {},
): Promise<MiscTriageResult> {
  const profile = await profileCtfArtifact(file, options)
  const base = emptyResult()
  base.commands.push(...profile.commands)
  base.artifacts.push(profile.artifact as unknown as Record<string, unknown>)
  base.observations.push(...profile.observations)
  base.limitations.push(...profile.limitations)

  const toolOutputs: Record<string, string | null> = {}
  await optionalProbe('binwalk', ['--', file.path], 'binwalk', toolOutputs, base, options)
  await optionalProbe('exiftool', [file.path], 'exiftool', toolOutputs, base, options)
  await optionalProbe('7z', ['l', file.path], '7z', toolOutputs, base, options)
  await optionalProbe('strings', ['-a', '-n', '6', '--', file.path], 'strings', toolOutputs, base, { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 80_000) })

  if (['.png', '.bmp'].includes(profile.artifact.extension)) {
    await optionalProbe('zsteg', [file.path], 'zsteg', toolOutputs, base, options)
  }

  if (['.pcap', '.pcapng'].includes(profile.artifact.extension) || /pcap|capture/i.test(profile.artifact.fileType ?? '')) {
    base.nextActions.push({ tool: 'ctf_pcap_profile', args: { path: profile.artifact.path }, reason: 'Artifact appears to be a packet capture.' })
  }
  if (/archive|zip|7-zip|rar|gzip|tar/i.test(profile.artifact.fileType ?? '') || ['.zip', '.rar', '.7z', '.gz', '.tar'].includes(profile.artifact.extension)) {
    base.humanRequired.push(makeHumanRequest({
      type: 'confirm',
      title: 'Confirm archive extraction',
      reason: 'Archive extraction creates derived files in the workspace; triage has only listed contents.',
      operationOrder: [
        {
          order: 1,
          kind: 'instruction',
          title: 'Confirm extraction target',
          instruction: 'Confirm an output directory under working/ for extraction and provide any archive password if known.',
          expectedSignal: 'Return a log line with outputDirectory and optional password text.',
        },
      ],
      acceptedReturnTypes: ['log', 'ocr_text'],
      legacySteps: ['Confirm an output directory under working/ for extraction.', 'Provide any password if the archive is encrypted.'],
      expectedResult: { outputDirectory: 'relative working directory', password: 'optional password' },
      returnFields: {
        log: 'outputDirectory and optional password',
        ocr_text: 'recognized text containing outputDirectory and optional password',
      },
    }))
  }

  return { ...base, status: base.humanRequired.length > 0 ? 'human_required' : 'ok', artifact: profile.artifact, toolOutputs }
}

export async function profilePcapArtifact(
  file: ResolvedWorkspaceFile,
  options: CommandOptions = {},
): Promise<MiscTriageResult> {
  const profile = await profileCtfArtifact(file, options)
  const base = emptyResult()
  base.commands.push(...profile.commands)
  base.artifacts.push(profile.artifact as unknown as Record<string, unknown>)
  base.observations.push(...profile.observations)
  base.limitations.push(...profile.limitations)
  const toolOutputs: Record<string, string | null> = {}

  const tshark = await findCtfExecutable('tshark', options.cwd)
  if (!tshark) {
    base.status = 'missing_capability'
    base.limitations.push('tshark is not installed; pcap conversation and protocol hierarchy were skipped.')
    base.nextActions.push({ tool: 'ctf_misc_triage', args: { path: profile.artifact.path }, reason: 'Run generic artifact triage while pcap tooling is unavailable.' })
    return { ...base, artifact: profile.artifact, toolOutputs }
  }

  for (const [label, argv] of [
    ['protocolHierarchy', ['-r', file.path, '-q', '-z', 'io,phs']],
    ['tcpConversations', ['-r', file.path, '-q', '-z', 'conv,tcp']],
    ['udpConversations', ['-r', file.path, '-q', '-z', 'conv,udp']],
  ] as const) {
    const capture = await runCommand(tshark, argv, options)
    base.commands.push(commandRecord(tshark, argv, capture, options.cwd))
    toolOutputs[label] = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null
  }

  base.observations.push('tshark protocol hierarchy and TCP/UDP conversation summaries recorded.')
  base.nextActions.push({ tool: 'ctf_http_request', args: {}, reason: 'If HTTP endpoints or hosts are identified, replay a baseline request with ctf_http_request.' })
  return { ...base, artifact: profile.artifact, toolOutputs }
}

async function optionalProbe(
  executableName: string,
  argv: string[],
  outputKey: string,
  outputs: Record<string, string | null>,
  base: CtfToolResultBase,
  options: CommandOptions,
): Promise<void> {
  const executable = await findCtfExecutable(executableName, options.cwd)
  if (!executable) {
    base.limitations.push(`${executableName} is not installed.`)
    outputs[outputKey] = null
    return
  }
  const capture = await runCommand(executable, argv, options)
  base.commands.push(commandRecord(executable, argv, capture, options.cwd))
  outputs[outputKey] = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null
  base.observations.push(`${executableName} probe ${capture.ok ? 'completed' : `exited with ${capture.exitCode ?? 'no status'}`}.`)
}
