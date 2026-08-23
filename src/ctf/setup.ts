import { createHumanRequest, type HumanRequestResult } from './human.js'
import type { CtfHumanOperation, CtfHumanRequest } from './types.js'

export type CtfSetupTarget =
  | 'gdb_pwndbg'
  | 'ida_pro'
  | 'r2'
  | 'chrome_devtools_mcp'
  | 'mitmproxy'
  | 'blackarch_repo'

export interface ToolSetupRequestResult extends HumanRequestResult {
  target: CtfSetupTarget
}

export function createToolSetupRequest(
  target: CtfSetupTarget,
  context?: string,
): ToolSetupRequestResult {
  const request = createHumanRequest(buildSetupRequest(target, context))
  return {
    ...request,
    target,
  }
}

function buildSetupRequest(target: CtfSetupTarget, context?: string): CtfHumanRequest {
  switch (target) {
    case 'gdb_pwndbg':
      return requestFromOperations(
        'start_service',
        'Install or refresh GDB with Pwndbg',
        'GDB/Pwndbg is missing or needs a clean reinstall.',
        [
          {
            order: 1,
            kind: 'command',
            title: 'Install Pwndbg',
            command: "curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb",
            expectedSignal: 'Return the installer log and confirm it completed without errors.',
          },
          {
            order: 2,
            kind: 'command',
            title: 'Verify pwndbg loads in GDB',
            command: "gdb -q -batch -ex 'python import pwndbg'",
            expectedSignal: 'Return pwndbg load output or any import failure text.',
          },
          {
            order: 3,
            kind: 'instruction',
            title: 'Record the usable path',
            instruction: 'Return the exact working GDB command and any package manager notes needed for later reuse.',
            expectedSignal: 'Return log or OCR text with the installed path and verification result.',
          },
        ],
        context,
        {
          log: 'installer output, GDB version, and pwndbg load confirmation',
          screenshot: 'installer or terminal screenshot text showing the successful setup',
          ocr_text: 'recognized text containing the install path or verification result',
        },
      )
    case 'ida_pro':
      return requestFromOperations(
        'start_service',
        'Install IDA Pro and prepare an IDAPython workflow',
        'IDA is not configured locally, but the next RE step needs an IDAPython script-based workflow.',
        [
          {
            order: 1,
            kind: 'instruction',
            title: 'Install and expose IDA',
            instruction: 'Install IDA Pro, then ensure idat64, idat, ida64, or ida is reachable from the local PATH or a known absolute path.',
            expectedSignal: 'Return a log or OCR line showing the CLI path that was found.',
          },
          {
            order: 2,
            kind: 'command',
            title: 'Run an IDAPython script in batch mode',
            command: 'idat64 -A -Sanalysis.py chall.bin',
            expectedSignal: 'Return the analysis log produced by IDAPython or the exact command failure.',
          },
          {
            order: 3,
            kind: 'instruction',
            title: 'Confirm script handoff',
            instruction: 'Return the script path, input binary, and the first question the script should answer.',
            expectedSignal: 'Return log or OCR text with the script path and analysis goal.',
          },
        ],
        context,
        {
          log: 'IDA CLI path, batch-mode log, and the analysis goal',
          screenshot: 'IDA UI or terminal screenshot text showing the script handoff',
          ocr_text: 'recognized text containing the CLI path and batch command',
        },
      )
    case 'r2':
      return requestFromOperations(
        'start_service',
        'Install or refresh radare2',
        'radare2 is missing or needs a consistent local build.',
        [
          {
            order: 1,
            kind: 'command',
            title: 'Clone radare2',
            command: 'git clone https://github.com/radareorg/radare2.git',
            expectedSignal: 'Return the clone log and confirm the repository path exists.',
          },
          {
            order: 2,
            kind: 'command',
            title: 'Install radare2',
            command: 'cd radare2 && sys/install.sh',
            expectedSignal: 'Return the build/install log from sys/install.sh.',
          },
          {
            order: 3,
            kind: 'command',
            title: 'Verify r2',
            command: 'r2 -v',
            expectedSignal: 'Return the radare2 version banner.',
          },
        ],
        context,
        {
          log: 'clone log, install log, and r2 version',
          screenshot: 'terminal screenshot text showing the completed install',
          ocr_text: 'recognized text with the repository path or version banner',
        },
      )
    case 'chrome_devtools_mcp':
      return requestFromOperations(
        'start_service',
        'Configure Chrome DevTools MCP',
        'The browser automation path needs a local Chrome DevTools MCP server.',
        [
          {
            order: 1,
            kind: 'command',
            title: 'Test the MCP server',
            command: 'npx --yes chrome-devtools-mcp@latest --help',
            expectedSignal: 'Return the chrome-devtools-mcp help text or install prompt text.',
          },
          {
            order: 2,
            kind: 'instruction',
            title: 'Add the MCP entry',
            instruction: 'Add a stdio MCP entry pointing to npx chrome-devtools-mcp@latest in the client configuration, then restart the client.',
            expectedSignal: 'Return log or OCR text showing the added MCP entry and restart result.',
          },
          {
            order: 3,
            kind: 'instruction',
            title: 'Confirm browser automation works',
            instruction: 'Open a local page or target site through the configured MCP and return the resulting log or screenshot text.',
            expectedSignal: 'Return log, screenshot text, or OCR text from the browser automation session.',
          },
        ],
        context,
        {
          log: 'MCP help output and client restart logs',
          screenshot: 'client configuration or browser session screenshot text',
          ocr_text: 'recognized text containing the MCP entry or server status',
        },
      )
    case 'mitmproxy':
      return requestFromOperations(
        'start_service',
        'Install and configure mitmproxy',
        'A live web capture tool is needed for HTTP(S) proxy capture.',
        [
          {
            order: 1,
            kind: 'command',
            title: 'Install mitmproxy on Arch/BlackArch',
            command: 'sudo pacman -S --needed mitmproxy',
            expectedSignal: 'Return the package installation log or the exact package-manager error.',
          },
          {
            order: 2,
            kind: 'command',
            title: 'Verify mitmproxy',
            command: 'mitmweb --version',
            expectedSignal: 'Return the installed mitmproxy version banner.',
          },
          {
            order: 3,
            kind: 'command',
            title: 'Start mitmweb',
            command: 'mitmweb --listen-port 8080 --web-host 127.0.0.1',
            expectedSignal: 'Return the proxy startup log and confirm the listen port.',
          },
          {
            order: 4,
            kind: 'instruction',
            title: 'Trust the proxy CA',
            instruction: 'Open http://mitm.it in the browser or device that will be proxied and install the mitmproxy CA certificate.',
            expectedSignal: 'Return the browser log, screenshot, or OCR text showing the certificate installation page or success state.',
          },
          {
            order: 5,
            kind: 'command',
            title: 'Verify traffic capture',
            command: "curl --proxy 127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com/",
            expectedSignal: 'Return the captured HTTP output and confirm the proxy sees the request.',
          },
        ],
        context,
        {
          log: 'mitmweb startup log, certificate trust confirmation, and curl verification output',
          screenshot: 'proxy UI or browser screenshot text showing captured flows',
          ocr_text: 'recognized text showing the proxy port or certificate trust screen',
        },
      )
    case 'blackarch_repo':
      return requestFromOperations(
        'start_service',
        'Add the BlackArch repository',
        'Additional pentest packages will be installed from BlackArch.',
        [
          {
            order: 1,
            kind: 'command',
            title: 'Download the BlackArch strap script',
            command: 'curl -O https://blackarch.org/strap.sh',
            expectedSignal: 'Return the download log and confirm the script is present.',
          },
          {
            order: 2,
            kind: 'command',
            title: 'Enable the repository',
            command: 'chmod +x strap.sh && sudo ./strap.sh',
            expectedSignal: 'Return the strap installer log.',
          },
          {
            order: 3,
            kind: 'command',
            title: 'Refresh package metadata',
            command: 'sudo pacman -Syu',
            expectedSignal: 'Return the system update log after the repository is enabled.',
          },
          {
            order: 4,
            kind: 'instruction',
            title: 'Install the required BlackArch categories',
            instruction: 'Install only the categories you need, for example blackarch-reversing, blackarch-exploitation, blackarch-webapp, or blackarch-fuzzer.',
            expectedSignal: 'Return log or OCR text showing the installed package names.',
          },
        ],
        context,
        {
          log: 'strap script output, pacman refresh output, and installed categories',
          screenshot: 'terminal or package-manager screenshot text',
          ocr_text: 'recognized text containing the selected BlackArch categories',
        },
      )
  }
}

function requestFromOperations(
  type: CtfHumanRequest['type'],
  title: string,
  reason: string,
  operationOrder: CtfHumanOperation[],
  context: string | undefined,
  returnFields: Record<string, string>,
): CtfHumanRequest {
  return {
    type,
    title,
    reason: context ? `${reason} Context: ${context}` : reason,
    operationOrder,
    acceptedReturnTypes: ['log', 'screenshot', 'ocr_text'],
    returnContract: {
      onlyReturn: ['log', 'screenshot', 'ocr_text'],
      format: 'plain_text',
      fields: returnFields,
    },
    legacySteps: operationOrder.map(step => step.command ?? step.instruction ?? step.title),
  }
}
