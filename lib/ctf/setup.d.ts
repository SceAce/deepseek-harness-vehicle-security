import { type HumanRequestResult } from './human.js';
export type CtfSetupTarget = 'gdb_pwndbg' | 'ida_pro' | 'r2' | 'chrome_mcp' | 'chrome_devtools_mcp' | 'mitmproxy' | 'python_ctf_env' | 'blackarch_repo';
export interface ToolSetupRequestResult extends HumanRequestResult {
    target: CtfSetupTarget;
}
export declare function createToolSetupRequest(target: CtfSetupTarget, context?: string): ToolSetupRequestResult;
//# sourceMappingURL=setup.d.ts.map