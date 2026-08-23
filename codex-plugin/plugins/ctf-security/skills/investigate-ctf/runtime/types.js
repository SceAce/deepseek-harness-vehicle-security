export function emptyResult(status = 'ok') {
    return {
        status,
        observations: [],
        commands: [],
        artifacts: [],
        limitations: [],
        nextActions: [],
        humanRequired: [],
    };
}
export function commandRecord(executable, argv, result, cwd) {
    return {
        executable,
        argv: [...argv],
        ...(cwd === undefined ? {} : { cwd }),
        ok: result.ok,
        exitCode: result.exitCode,
        stdout: result.stdout,
        stderr: result.stderr,
        error: result.error,
    };
}
//# sourceMappingURL=types.js.map