type CanFormat = 'candump' | 'asc';
type CanDirection = 'Rx' | 'Tx' | null;
export interface ParsedCanFrame {
    format: CanFormat;
    timestamp: number | null;
    channel: string;
    id: string;
    direction: CanDirection;
    dlc: number;
    dataHex: string;
}
export interface CanLogOptions {
    maxFrames?: number;
    idFilter?: string;
}
export interface CanLogSummary {
    format: CanFormat | 'unknown';
    totalLines: number;
    parsedFrames: number;
    uniqueIds: number;
    firstTimestamp: number | null;
    lastTimestamp: number | null;
    topIds: Array<{
        id: string;
        count: number;
        channels: string[];
    }>;
    sampleFrames: Array<Omit<ParsedCanFrame, 'format'>>;
}
export declare function parseCanLog(text: string, options?: CanLogOptions): CanLogSummary;
export {};
//# sourceMappingURL=can.d.ts.map