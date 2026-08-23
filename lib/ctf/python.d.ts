import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export interface CtfPythonExecArgs {
    code?: string;
    scriptPath?: string;
    argv?: string[];
}
export interface CtfPythonExecOptions extends CommandOptions {
    workspaceRoot?: string;
    maxFileBytes?: number;
}
export interface CtfPythonExecResult extends CtfToolResultBase {
    python: {
        executable: string | null;
        argv: string[];
        scriptPath: string | null;
    };
    output: string | null;
}
export declare function runCtfPython(args: CtfPythonExecArgs, options?: CtfPythonExecOptions): Promise<CtfPythonExecResult>;
//# sourceMappingURL=python.d.ts.map