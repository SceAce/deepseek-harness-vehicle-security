import type { Context } from '@deepseek-ai/cordis';
import Schema from '@deepseek-ai/schemastery';
export declare const name = "vehicle-security";
export declare const inject: string[];
export interface Config {
    workspaceRoot: string;
    maxFileBytes: number;
    maxOutputChars: number;
    commandTimeoutMs: number;
    enableBinwalk: boolean;
}
export declare const Config: Schema<Config>;
export declare function apply(ctx: Context, config: Config): void;
//# sourceMappingURL=index.d.ts.map