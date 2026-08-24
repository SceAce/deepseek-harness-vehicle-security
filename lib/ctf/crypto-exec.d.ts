import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export type CtfCryptoEngine = 'sage' | 'gp';
export interface CtfCryptoExecArgs {
    code?: string;
    scriptPath?: string;
    argv?: string[];
}
export interface CtfCryptoExecOptions extends CommandOptions {
    workspaceRoot?: string;
    maxFileBytes?: number;
}
export interface CtfCryptoExecResult extends CtfToolResultBase {
    engine: {
        name: CtfCryptoEngine;
        executable: string | null;
        argv: string[];
        scriptPath: string | null;
    };
    output: string | null;
}
export declare function runCtfCryptoEngine(engine: CtfCryptoEngine, args: CtfCryptoExecArgs, options?: CtfCryptoExecOptions): Promise<CtfCryptoExecResult>;
//# sourceMappingURL=crypto-exec.d.ts.map