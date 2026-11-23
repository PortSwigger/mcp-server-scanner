package com.mcpscanner.client;

import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.http.evidence.WireRecord;

import java.util.Optional;

record SseMessagePost(McpFlow.HttpResponse response, Optional<WireRecord> wire) {
}
