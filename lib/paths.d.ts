import { type Stats } from 'node:fs';
export interface ResolvedWorkspaceFile {
    root: string;
    path: string;
    relativePath: string;
    info: Stats;
}
export declare function resolveWorkspaceFile(workspaceRoot: string, inputPath: string, maxFileBytes: number): Promise<ResolvedWorkspaceFile>;
export declare function assertInside(root: string, candidate: string): void;
export declare function findExecutable(name: string, envPath?: string): Promise<string | null>;
//# sourceMappingURL=paths.d.ts.map