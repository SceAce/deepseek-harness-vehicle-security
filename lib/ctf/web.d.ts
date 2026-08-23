import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export interface HttpRequestArgs {
    url: string;
    method?: string;
    headers?: string[];
    body?: string;
    followRedirects?: boolean;
    maxTimeSeconds?: number;
}
export interface HttpRequestResult extends CtfToolResultBase {
    request: HttpRequestArgs;
    response: {
        statusCode: number | null;
        headerBytes: number;
        bodyBytes: number;
        bodySha256: string;
        preview: string;
    } | null;
}
export interface BrowserProbeResult extends CtfToolResultBase {
    browser: string | null;
    url: string;
    domPreview: string | null;
    title: string | null;
    screenshotPath: string | null;
}
export interface WebCaptureProbeResult extends CtfToolResultBase {
    proxy: string | null;
    version: string | null;
    launchCommand: string | null;
    verifyCommand: string | null;
}
export declare function httpRequest(args: HttpRequestArgs, options?: CommandOptions): Promise<HttpRequestResult>;
export declare function httpDiff(args: {
    urlA: string;
    urlB: string;
    method?: string;
    headers?: string[];
    bodyA?: string;
    bodyB?: string;
}, options?: CommandOptions): Promise<CtfToolResultBase & {
    left: HttpRequestResult;
    right: HttpRequestResult;
    diff: Record<string, unknown>;
}>;
export declare function probeWebBrowser(args: {
    url: string;
    captureScreenshot?: boolean;
}, options?: CommandOptions): Promise<BrowserProbeResult>;
export declare function probeWebCapture(args: {
    listenHost?: string;
    listenPort?: number;
    webPort?: number;
}, options?: CommandOptions): Promise<WebCaptureProbeResult>;
//# sourceMappingURL=web.d.ts.map