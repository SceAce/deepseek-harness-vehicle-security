export interface CtfPythonEnvironment {
    executable: string | null;
    source: string | null;
    venv: string | null;
    bin: string | null;
    searchPath: string;
}
export declare function discoverCtfPython(cwd?: string): Promise<CtfPythonEnvironment>;
export declare function findCtfExecutable(name: string, cwd?: string): Promise<string | null>;
export declare function ctfSearchPath(cwd?: string, selectedPythonBin?: string | null): Promise<string>;
//# sourceMappingURL=environment.d.ts.map