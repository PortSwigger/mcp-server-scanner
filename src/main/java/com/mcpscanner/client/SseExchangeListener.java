package com.mcpscanner.client;

import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.mcp.RawSseFrame;

interface SseExchangeListener {

    SseExchangeListener IGNORING = new SseExchangeListener() {
        @Override
        public void messagePosted(SseStreamOpening opening, McpRequests.Request request, SseMessagePost posted) {
        }

        @Override
        public void eventReceived(SseStreamOpening opening, RawSseFrame frame) {
        }
    };

    void messagePosted(SseStreamOpening opening, McpRequests.Request request, SseMessagePost posted);

    void eventReceived(SseStreamOpening opening, RawSseFrame frame);
}
