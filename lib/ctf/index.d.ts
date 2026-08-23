import type { Context } from '@deepseek-ai/cordis';
import Schema from '@deepseek-ai/schemastery';
export declare const name = "ctf-tools";
export declare const inject: string[];
export interface Config {
    workspaceRoot?: string;
    maxFileBytes: number;
    maxOutputChars: number;
    commandTimeoutMs: number;
}
export declare const Config: Schema<Config>;
export declare function apply(ctx: Context, config: Config): void;
//# sourceMappingURL=index.d.ts.map