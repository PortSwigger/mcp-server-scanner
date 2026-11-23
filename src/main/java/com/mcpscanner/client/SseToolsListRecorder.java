package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.core.protocol.McpRequestId;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.core.protocol.McpSse;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.RawSseFrame;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

final class SseToolsListRecorder implements SseExchangeListener {

    private record PendingToolsList(SseStreamOpening opening, McpRequestId id, WireRecord post) {

        boolean answeredBy(SseStreamOpening stream, RawSseFrame frame) {
            return opening == stream && answers(frame.text(), id);
        }
    }

    private final AtomicReference<PendingToolsList> pending = new AtomicReference<>();
    private final AtomicReference<List<HttpRequestResponse>> recorded = new AtomicReference<>();
    private final AtomicBoolean stopped = new AtomicBoolean();

    @Override
    public void messagePosted(SseStreamOpening opening, McpRequests.Request request, SseMessagePost posted) {
        if (listening() && posted.response().successful()) {
            posted.wire().ifPresent(wire -> toolsListId(request.body()).ifPresent(id ->
                    pending.set(new PendingToolsList(opening, id, wire))));
        }
    }

    @Override
    public void eventReceived(SseStreamOpening opening, RawSseFrame frame) {
        PendingToolsList list = pending.get();
        if (list != null && listening() && list.answeredBy(opening, frame)) {
            recorded.compareAndSet(null, opening.evidenceOf(list.post(), frame));
        }
    }

    void stop() {
        stopped.set(true);
        pending.set(null);
    }

    private boolean listening() {
        return !stopped.get() && recorded.get() == null;
    }

    List<HttpRequestResponse> recorded() {
        return Objects.requireNonNullElse(recorded.get(), List.of());
    }

    private static Optional<McpRequestId> toolsListId(String body) {
        try {
            JsonNode message = McpObjectMapper.INSTANCE.readTree(body);
            return McpMethods.TOOLS_LIST.equals(message.path("method").asText()) && message.has("id")
                    ? Optional.of(McpRequestId.parse(message.get("id").toString())) : Optional.empty();
        } catch (JacksonException | IllegalArgumentException notAnIdentifiedToolsList) {
            return Optional.empty();
        }
    }

    private static boolean answers(String frame, McpRequestId id) {
        try {
            return McpSse.reply(frame, id, BoundedBodyReader.MAX_RESPONSE_BYTES) != null;
        } catch (IllegalArgumentException notAReply) {
            return false;
        }
    }
}
