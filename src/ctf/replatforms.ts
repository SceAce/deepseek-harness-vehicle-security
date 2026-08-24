import { mkdir, readdir } from 'node:fs/promises'
import path from 'node:path'
import { profileCtfArtifact, type CtfArtifactProfile } from './artifact.js'
import { findCtfExecutable } from './environment.js'
import type { ResolvedWorkspaceFile } from '../paths.js'
import { runCommand, type CommandOptions } from '../process.js'
import { commandRecord, emptyResult, type CtfToolResultBase } from './types.js'

export interface CtfPlatformProfileResult extends CtfToolResultBase {
  platform: 'windows' | 'android' | 'multiarch'
  artifact: CtfArtifactProfile
  tools: Array<{
    name: string
    executable: string | null
    available: boolean
    output: string | null
  }>
  architecture: string | null
}

export interface CtfPlatformExecResult extends CtfToolResultBase {
  platform: 'android' | 'multiarch'
  executable: string | null
  argv: string[]
  output: string | null
  outputDir?: string | null
  files?: string[]
}

export async function profilePeArtifact(
  file: ResolvedWorkspaceFile,
  options: CommandOptions = {},
): Promise<CtfPlatformProfileResult> {
  const profile = await profileCtfArtifact(file, options)
  const base = baseFromArtifact(profile)
  const tools = []
  const readobj = await findCtfExecutable('llvm-readobj', options.cwd)
  const objdump = await findCtfExecutable('llvm-objdump', options.cwd)

  if (readobj) {
    const argv = ['--file-headers', '--sections', '--coff-imports', '--coff-exports', '--', file.path]
    const capture = await runCommand(readobj, argv, {
      ...options,
      maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
    })
    const output = joinOutput(capture.stdout, capture.stderr)
    base.commands.push(commandRecord(readobj, argv, capture, options.cwd))
    tools.push({ name: 'llvm-readobj', executable: readobj, available: capture.ok, output })
    if (capture.ok) base.observations.push('PE header, section, import, and export evidence collected with llvm-readobj.')
    else base.limitations.push(`llvm-readobj exited with ${capture.exitCode ?? 'no status'}.`)
  } else {
    tools.push({ name: 'llvm-readobj', executable: null, available: false, output: null })
  }

  if (objdump) {
    const argv = ['-p', '--', file.path]
    const capture = await runCommand(objdump, argv, {
      ...options,
      maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
    })
    const output = joinOutput(capture.stdout, capture.stderr)
    base.commands.push(commandRecord(objdump, argv, capture, options.cwd))
    tools.push({ name: 'llvm-objdump', executable: objdump, available: capture.ok, output })
    if (capture.ok) base.observations.push('PE private headers and loader metadata collected with llvm-objdump.')
    else base.limitations.push(`llvm-objdump exited with ${capture.exitCode ?? 'no status'}.`)
  } else {
    tools.push({ name: 'llvm-objdump', executable: null, available: false, output: null })
  }

  if (!readobj && !objdump) {
    base.status = 'missing_capability'
    base.limitations.push('PE analysis needs llvm-readobj or llvm-objdump.')
    base.nextActions.push({
      tool: 'ctf_tool_setup',
      args: { target: 'windows_re' },
      reason: 'Install LLVM binutils or the Windows reverse-engineering toolchain.',
    })
  } else {
    base.nextActions.push({
      tool: 'ctf_re_ida_script',
      args: { path: file.relativePath, focus: 'PE imports exports entrypoint' },
      reason: 'Use IDA MCP/IDAPython when control-flow, types, or xrefs require database state.',
    })
    base.nextActions.push({
      tool: 'ctf_re_r2_query',
      args: { path: file.relativePath, commands: ['iI', 'iE', 'ii', 'afl'] },
      reason: 'Use radare2 for focused PE metadata, imports, exports, and functions.',
    })
  }

  return {
    ...base,
    status: base.status === 'missing_capability' ? base.status : 'ok',
    platform: 'windows',
    artifact: profile.artifact,
    tools,
    architecture: inferArchitecture(tools.map(item => item.output).filter(Boolean).join('\n')),
  }
}

export async function profileAndroidArtifact(
  file: ResolvedWorkspaceFile,
  options: CommandOptions = {},
): Promise<CtfPlatformProfileResult> {
  const profile = await profileCtfArtifact(file, options)
  const base = baseFromArtifact(profile)
  const tools = []
  const aapt2 = await findCtfExecutable('aapt2', options.cwd)
  const jadx = await findCtfExecutable('jadx', options.cwd)
  const adb = await findCtfExecutable('adb', options.cwd)
  const frida = await findCtfExecutable('frida', options.cwd)

  if (aapt2) {
    const argv = ['dump', 'badging', '--', file.path]
    const capture = await runCommand(aapt2, argv, {
      ...options,
      maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 80_000),
    })
    const output = joinOutput(capture.stdout, capture.stderr)
    base.commands.push(commandRecord(aapt2, argv, capture, options.cwd))
    tools.push({ name: 'aapt2', executable: aapt2, available: capture.ok, output })
    if (capture.ok) base.observations.push('Android manifest/package metadata collected with aapt2.')
    else base.limitations.push(`aapt2 dump badging exited with ${capture.exitCode ?? 'no status'}.`)
  } else {
    tools.push({ name: 'aapt2', executable: null, available: false, output: null })
  }

  for (const [name, executable, argv] of [
    ['jadx', jadx, ['--version']],
    ['adb', adb, ['version']],
    ['frida', frida, ['--version']],
  ] as Array<[string, string | null, string[]]>) {
    if (!executable) {
      tools.push({ name, executable: null, available: false, output: null })
      continue
    }
    const capture = await runCommand(executable, argv, options)
    const output = joinOutput(capture.stdout, capture.stderr)
    base.commands.push(commandRecord(executable, argv, capture, options.cwd))
    tools.push({ name, executable, available: capture.ok, output })
    if (!capture.ok) base.limitations.push(`${name} capability probe exited with ${capture.exitCode ?? 'no status'}.`)
  }

  const hasStatic = tools.some(item => item.name === 'aapt2' && item.available)
    || tools.some(item => item.name === 'jadx' && item.available)
  if (!hasStatic) {
    base.status = 'missing_capability'
    base.limitations.push('Android static analysis needs aapt2 or jadx.')
    base.nextActions.push({
      tool: 'ctf_tool_setup',
      args: { target: 'android_re' },
      reason: 'Install Android build tools and a Dex/APK decompiler.',
    })
  } else {
    base.nextActions.push({
      tool: 'ctf_re_ida_script',
      args: { path: file.relativePath, focus: 'Android manifest exported component WebView crypto flag' },
      reason: 'Use IDA MCP/IDAPython when native .so libraries are present inside the APK.',
    })
    base.nextActions.push({
      tool: 'ctf_human_request',
      args: { type: 'attach_device' },
      reason: 'Use a human-operated emulator/device only when runtime UI, logcat, or Frida attachment is required.',
    })
  }

  return {
    ...base,
    status: base.status === 'missing_capability' ? base.status : 'ok',
    platform: 'android',
    artifact: profile.artifact,
    tools,
    architecture: inferArchitecture(tools.map(item => item.output).filter(Boolean).join('\n')),
  }
}

export async function profileMultiarchArtifact(
  file: ResolvedWorkspaceFile,
  options: CommandOptions = {},
): Promise<CtfPlatformProfileResult> {
  const profile = await profileCtfArtifact(file, options)
  const base = baseFromArtifact(profile)
  const tools = []
  const readelf = await findCtfExecutable('readelf', options.cwd)
  const llvmReadobj = await findCtfExecutable('llvm-readobj', options.cwd)
  const qemuArm = await findCtfExecutable('qemu-arm', options.cwd)
  const qemuAarch64 = await findCtfExecutable('qemu-aarch64', options.cwd)

  for (const [name, executable, argv] of [
    ['readelf', readelf, ['-hW', '--', file.path]],
    ['llvm-readobj', llvmReadobj, ['--file-headers', '--', file.path]],
  ] as const) {
    if (!executable) {
      tools.push({ name, executable: null, available: false, output: null })
      continue
    }
    const capture = await runCommand(executable, argv, options)
    const output = joinOutput(capture.stdout, capture.stderr)
    base.commands.push(commandRecord(executable, argv, capture, options.cwd))
    tools.push({ name, executable, available: capture.ok, output })
    if (!capture.ok) base.limitations.push(`${name} architecture probe exited with ${capture.exitCode ?? 'no status'}.`)
  }

  for (const [name, executable] of [
    ['qemu-arm', qemuArm],
    ['qemu-aarch64', qemuAarch64],
  ] as Array<[string, string | null]>) {
    tools.push({ name, executable, available: Boolean(executable), output: executable ? 'user-mode emulator detected' : null })
  }

  if (!readelf && !llvmReadobj) {
    base.status = 'missing_capability'
    base.limitations.push('Multi-architecture analysis needs readelf or llvm-readobj.')
    base.nextActions.push({
      tool: 'ctf_tool_setup',
      args: { target: 'arm_re' },
      reason: 'Install architecture-aware binutils, QEMU user mode, and a multi-architecture debugger.',
    })
  } else {
    base.nextActions.push({
      tool: 'ctf_re_r2_query',
      args: { path: file.relativePath, commands: ['iI', 'ij', 'afl'] },
      reason: 'Use radare2 for architecture-neutral disassembly and metadata queries.',
    })
    base.nextActions.push({
      tool: 'ctf_re_ida_script',
      args: { path: file.relativePath, focus: 'ARM AArch64 calling convention entrypoint' },
      reason: 'Use IDA MCP/IDAPython when architecture-specific types and xrefs are needed.',
    })
  }

  return {
    ...base,
    status: base.status === 'missing_capability' ? base.status : 'ok',
    platform: 'multiarch',
    artifact: profile.artifact,
    tools,
    architecture: inferArchitecture(tools.map(item => item.output).filter(Boolean).join('\n')),
  }
}

export async function decompileAndroidArtifact(
  file: ResolvedWorkspaceFile,
  options: CommandOptions = {},
): Promise<CtfPlatformExecResult> {
  const base = emptyResult()
  const jadx = await findCtfExecutable('jadx', options.cwd)
  if (!jadx) {
    base.status = 'missing_capability'
    base.limitations.push('jadx is not installed.')
    base.nextActions.push({
      tool: 'ctf_tool_setup',
      args: { target: 'android_re' },
      reason: 'Install JADX before decompiling an APK or DEX artifact.',
    })
    return {
      ...base,
      platform: 'android',
      executable: null,
      argv: [],
      output: null,
      outputDir: null,
      files: [],
    }
  }

  const stem = path.basename(file.relativePath).replace(/[^A-Za-z0-9._-]+/g, '_')
  const outputDir = path.join(file.root, '.dsh-ctf-jadx', stem)
  await mkdir(outputDir, { recursive: true })
  const argv = ['-d', outputDir, file.path]
  const capture = await runCommand(jadx, argv, {
    ...options,
    maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
  })
  const output = joinOutput(capture.stdout, capture.stderr)
  base.commands.push(commandRecord(jadx, argv, capture, options.cwd))
  const files = capture.ok ? await listRelativeFiles(outputDir, file.root) : []
  base.observations.push(capture.ok
    ? `JADX decompilation completed with ${files.length} generated files.`
    : `JADX exited with ${capture.exitCode ?? 'no status'}.`)
  if (!capture.ok) base.limitations.push(capture.error ?? capture.stderr.trim())
  base.nextActions.push({
    tool: 'ctf_python_exec',
    args: {
      code: `from pathlib import Path\nroot = Path(${JSON.stringify(path.relative(file.root, outputDir))})\nprint("\\n".join(str(item) for item in sorted(root.rglob("*")) if item.is_file()))`,
    },
    reason: 'Use the fixed CTF Python environment to parse or search generated Java/XML output when needed.',
  })
  return {
    ...base,
    status: capture.ok ? 'ok' : 'failed',
    platform: 'android',
    executable: jadx,
    argv,
    output,
    outputDir: path.relative(file.root, outputDir),
    files: files.slice(0, 500),
  }
}

export async function executeMultiarchArtifact(
  file: ResolvedWorkspaceFile,
  args: {
    architecture?: 'arm' | 'aarch64'
    argv?: string[]
  },
  options: CommandOptions = {},
): Promise<CtfPlatformExecResult> {
  const architecture = args.architecture ?? 'aarch64'
  const executableName = architecture === 'arm' ? 'qemu-arm' : 'qemu-aarch64'
  const emulator = await findCtfExecutable(executableName, options.cwd)
  const targetArgv = [file.path, ...(Array.isArray(args.argv) ? args.argv.slice(0, 32).map(String) : [])]
  if (!emulator) {
    const base = emptyResult('missing_capability')
    base.limitations.push(`${executableName} is not installed.`)
    base.nextActions.push({
      tool: 'ctf_tool_setup',
      args: { target: 'arm_re' },
      reason: 'Install QEMU user-mode emulation before executing the selected architecture.',
    })
    return {
      ...base,
      platform: 'multiarch',
      executable: null,
      argv: targetArgv,
      output: null,
    }
  }

  const capture = await runCommand(emulator, targetArgv, {
    ...options,
    maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
  })
  const output = joinOutput(capture.stdout, capture.stderr)
  const base = emptyResult(capture.ok ? 'ok' : 'failed')
  base.commands.push(commandRecord(emulator, targetArgv, capture, options.cwd))
  base.observations.push(`Executed ${architecture} artifact through ${executableName}.`)
  if (!capture.ok) base.limitations.push(capture.error ?? capture.stderr.trim())
  return {
    ...base,
    platform: 'multiarch',
    executable: emulator,
    argv: targetArgv,
    output,
  }
}

function baseFromArtifact(profile: Awaited<ReturnType<typeof profileCtfArtifact>>): CtfToolResultBase {
  const base = emptyResult()
  base.commands.push(...profile.commands)
  base.artifacts.push(profile.artifact as unknown as Record<string, unknown>)
  base.observations.push(...profile.observations)
  base.limitations.push(...profile.limitations)
  return base
}

async function listRelativeFiles(root: string, workspaceRoot: string): Promise<string[]> {
  const result: string[] = []
  async function visit(directory: string): Promise<void> {
    let entries
    try {
      entries = await readdir(directory, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name)
      if (entry.isDirectory()) await visit(fullPath)
      else if (entry.isFile()) result.push(path.relative(workspaceRoot, fullPath))
    }
  }
  await visit(root)
  return result.sort()
}

function joinOutput(stdout: string, stderr: string): string | null {
  return [stdout, stderr].filter(Boolean).join('\n').trim() || null
}

function inferArchitecture(output: string): string | null {
  const match = output.match(/\b(AArch64|ARM64|ARM|x86-64|x86|i[3-6]86|Intel 386|PowerPC|MIPS|RISC-V|WebAssembly)\b/i)
  return match?.[1] ?? null
}
