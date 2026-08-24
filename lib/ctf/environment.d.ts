import type { CommandOptions, CommandResult } from '../process.js';
export interface CtfPythonEnvironment {
    policy: 'fixed';
    requiredExecutable: string;
    executable: string | null;
    source: string | null;
    venv: string | null;
    bin: string | null;
    searchPath: string;
}
export declare const DEFAULT_CTF_PYTHON = "/home/source/tools/PyVenv/CTF/bin/python";
export declare const DEFAULT_CTF_IDA_CLI_CANDIDATES: readonly ["/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/idat64", "/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/idat", "/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/ida64", "/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/ida"];
export declare function discoverCtfPython(cwd?: string): Promise<CtfPythonEnvironment>;
export declare function findCtfExecutable(name: string, cwd?: string): Promise<string | null>;
export declare function ctfCommandOptions(executable: string, options?: CommandOptions): CommandOptions;
export declare function isRubyGemBackendFailure(result: Pick<CommandResult, 'stdout' | 'stderr' | 'error'>): boolean;
export declare function findCtfIdaExecutable(cwd?: string): Promise<string | null>;
export declare function ctfSearchPath(cwd?: string, selectedPythonBin?: string | null): Promise<string>;
//# sourceMappingURL=environment.d.ts.map