interface TransportPayload {
    type: 'raw' | 'isotp-single' | 'isotp-first';
    payload: number[];
}
export interface UdsDecodeResult {
    rawHex: string;
    payloadHex: string;
    transport: TransportPayload['type'];
    responseType: 'request' | 'positive' | 'negative';
    requestServiceId: string;
    service: string;
    dataHex: string;
    serviceId?: string;
    negativeResponseCode?: string;
    negativeResponse?: string;
    dataIdentifier?: string;
    securityLevel?: number;
    securityAccessOperation?: 'requestSeed' | 'sendKey';
    sessionType?: string;
    routineControlType?: string;
    routineIdentifier?: string;
}
export declare function parseHexBytes(input: string): number[];
export declare function decodeUds(input: string, stripIsoTp?: boolean): UdsDecodeResult;
export {};
//# sourceMappingURL=uds.d.ts.map