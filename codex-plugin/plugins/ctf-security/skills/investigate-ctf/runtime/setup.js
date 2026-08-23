import { createHumanRequest } from './human.js';
export function createToolSetupRequest(target, context) {
    const request = createHumanRequest(buildSetupRequest(target, context));
    return {
        ...request,
        target,
    };
}
function buildSetupRequest(target, context) {
    switch (target) {
        case 'gdb_pwndbg':
            return requestFromOperations('start_service', 'Install or refresh GDB with Pwndbg', 'GDB/Pwndbg is missing or needs a clean reinstall.', [
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
            ], context, {
                log: 'installer output, GDB version, and pwndbg load confirmation',
                screenshot: 'installer or terminal screenshot text showing the successful setup',
                ocr_text: 'recognized text containing the install path or verification result',
            });
        case 'ida_pro':
            return requestFromOperations('start_service', 'Verify the IDA MCP and optional IDA CLI fallback', 'IDA MCP should be the primary RE integration. IDA CLI is only needed when batch execution outside the MCP is specifically required.', [
                {
                    order: 1,
                    kind: 'instruction',
                    title: 'Confirm the IDA MCP',
                    instruction: 'Use the already configured IDA MCP to open the challenge database or attach the target binary, then return the MCP/client status text.',
                    expectedSignal: 'Return log or OCR text showing the IDA MCP server and target database are available.',
                },
                {
                    order: 2,
                    kind: 'instruction',
                    title: 'Check the optional CLI fallback',
                    instruction: 'Only if batch execution is needed, expose idat64, idat, ida64, or ida on PATH and return the resolved path.',
                    expectedSignal: 'Return a log or OCR line with the optional IDA CLI path, or state that the MCP path is sufficient.',
                },
                {
                    order: 3,
                    kind: 'command',
                    title: 'Verify IDAPython only when CLI exists',
                    command: 'command -v idat64 || command -v idat || command -v ida64 || command -v ida || true',
                    expectedSignal: 'Return the command output; an empty result is acceptable when IDA MCP is the selected execution path.',
                },
            ], context, {
                log: 'IDA MCP status and optional CLI path',
                screenshot: 'IDA UI or terminal screenshot text showing the script handoff',
                ocr_text: 'recognized text containing the MCP status or optional CLI path',
            });
        case 'r2':
            return requestFromOperations('start_service', 'Install or refresh radare2', 'radare2 is missing or needs a consistent local build.', [
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
            ], context, {
                log: 'clone log, install log, and r2 version',
                screenshot: 'terminal screenshot text showing the completed install',
                ocr_text: 'recognized text with the repository path or version banner',
            });
        case 'chrome_mcp':
        case 'chrome_devtools_mcp':
            return requestFromOperations('start_service', 'Verify mcp-chrome browser bridge', 'The browser automation path uses the installed mcp-chrome bridge; the AI writes the MCP JSON and the human only confirms the bridge/extension state.', [
                {
                    order: 1,
                    kind: 'command',
                    title: 'Check the local bridge endpoint',
                    command: 'curl -sS --max-time 5 http://127.0.0.1:12306/mcp',
                    expectedSignal: 'Return the bridge response or the exact connection error.',
                },
                {
                    order: 2,
                    kind: 'instruction',
                    title: 'Confirm the Chrome extension bridge',
                    instruction: 'Ensure the mcp-chrome extension/bridge is running in the intended Chrome profile and return its visible status.',
                    expectedSignal: 'Return log, screenshot, or OCR text showing the bridge is running.',
                },
                {
                    order: 3,
                    kind: 'instruction',
                    title: 'Confirm browser automation works',
                    instruction: 'Open a local page through the configured mcp-chrome MCP and return the resulting log or screenshot text.',
                    expectedSignal: 'Return log, screenshot text, or OCR text from the browser automation session.',
                },
            ], context, {
                log: 'bridge endpoint response and browser automation logs',
                screenshot: 'client configuration or browser session screenshot text',
                ocr_text: 'recognized text containing the MCP entry or server status',
            });
        case 'python_ctf_env':
            return requestFromOperations('start_service', 'Verify the CTF Python virtual environment', 'The CTF tool layer should use the existing Python environment before installing or scripting around missing libraries.', [
                {
                    order: 1,
                    kind: 'command',
                    title: 'Verify the selected interpreter',
                    command: 'source /home/source/tools/PyVenv/CTF/bin/activate && python --version && python -m pip --version',
                    expectedSignal: 'Return the Python and pip version output.',
                },
                {
                    order: 2,
                    kind: 'command',
                    title: 'Verify core CTF modules',
                    command: 'source /home/source/tools/PyVenv/CTF/bin/activate && python -c \'import pwn, z3, sympy, Crypto, gmpy2, requests, PIL, unicorn, capstone, lief, bs4; print("ctf-modules-ok")\'',
                    expectedSignal: 'Return ctf-modules-ok or the first missing import.',
                },
                {
                    order: 3,
                    kind: 'instruction',
                    title: 'Report only missing modules',
                    instruction: 'If a required module is missing, return its import name and let the AI generate the exact install command for this venv.',
                    expectedSignal: 'Return log or OCR text listing missing imports; do not paste secrets.',
                },
            ], context, {
                log: 'Python/pip versions and module verification output',
                screenshot: 'terminal screenshot text showing the active venv',
                ocr_text: 'recognized text containing the interpreter path or missing modules',
            });
        case 'mitmproxy':
            return requestFromOperations('start_service', 'Install and configure mitmproxy', 'A live web capture tool is needed for HTTP(S) proxy capture.', [
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
            ], context, {
                log: 'mitmweb startup log, certificate trust confirmation, and curl verification output',
                screenshot: 'proxy UI or browser screenshot text showing captured flows',
                ocr_text: 'recognized text showing the proxy port or certificate trust screen',
            });
        case 'blackarch_repo':
            return requestFromOperations('start_service', 'Add the BlackArch repository', 'Additional pentest packages will be installed from BlackArch.', [
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
            ], context, {
                log: 'strap script output, pacman refresh output, and installed categories',
                screenshot: 'terminal or package-manager screenshot text',
                ocr_text: 'recognized text containing the selected BlackArch categories',
            });
    }
}
function requestFromOperations(type, title, reason, operationOrder, context, returnFields) {
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
    };
}
//# sourceMappingURL=setup.js.map