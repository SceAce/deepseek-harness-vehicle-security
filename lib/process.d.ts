export interface CommandOptions {
    signal?: AbortSignal;
    timeoutMs?: number;
    maxOutputChars?: number;
    cwd?: string;
    env?: NodeJS.ProcessEnv;
}
export interface CommandResult {
    ok: boolean;
    exitCode: number | null;
    stdout: string;
    stderr: string;
    error: string | null;
}
export declare function runCommand(command: string, args: readonly string[], options?: CommandOptions): Promise<CommandResult>;
export declare function truncate(value: string, maxChars: number): string;
//# sourceMappingURL=process.d.ts.map