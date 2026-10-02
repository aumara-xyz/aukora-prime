interface BodyReceipt {
    readonly sessionId: string;
    readonly line: string;
    readonly turn: number;
    readonly spokenAt: number;
    readonly request_uuid: string;
    readonly body_sha256: string;
    readonly source_citation: {
        readonly sessionId: string;
        readonly turn: number;
        readonly sha256: string;
        readonly requestId: string;
    };
    readonly citations: readonly {
        readonly source_id: string;
        readonly url: string;
        readonly captured_at: string;
        readonly span_sha256: string;
    }[];
}
export type PilotInferenceResult = {
    readonly outcome: 'completed';
    readonly request_uuid: string;
    readonly mode: 'mock' | 'production';
    readonly route_id: 'externalDeepSeek';
    readonly proposal: {
        readonly text: string;
        readonly source_ids: readonly string[];
        readonly grantsAuthority: false;
    };
    readonly usage: {
        readonly input_tokens: number;
        readonly output_tokens: number;
        readonly cost_microusd: number;
    };
    readonly receipt: BodyReceipt;
    readonly omitted: readonly {
        readonly reason: string;
    }[];
} | {
    readonly outcome: 'outcome_unknown';
    readonly request_uuid: string;
    readonly receipt: BodyReceipt;
    readonly error: string;
    readonly reservation_retained: true;
};
export declare function AumaReplyView({ result }: {
    result: PilotInferenceResult | null;
}): import("react").JSX.Element;
export {};
//# sourceMappingURL=AumaReplyView.d.ts.map