package com.mcpscanner.mcp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;

public final class SseResponseParser {

    private static final int MAX_EVENT_BYTES = 1024 * 1024;
    private static final int MAX_ENDPOINT_SCAN_BYTES = 256 * 1024;
    private static final int MAX_RESPONSE_EVENTS = 4096;
    private static final String ENDPOINT_EVENT = "endpoint";
    private static final String EVENT_STREAM_MEDIA_TYPE = "text/event-stream";
    private static final String FRAME_TERMINATOR = "\n\n";
    private static final String LINE_OVERFLOW = "SSE line exceeded " + MAX_EVENT_BYTES + " bytes";
    private static final SseFrameReader.Limits EVENT_LIMITS = new SseFrameReader.Limits(
            MAX_EVENT_BYTES, 2L * MAX_EVENT_BYTES, LINE_OVERFLOW, Long.MAX_VALUE, LINE_OVERFLOW);
    private static final SseFrameReader.Limits RESPONSE_LIMITS = new SseFrameReader.Limits(
            MAX_EVENT_BYTES, BoundedBodyReader.MAX_RESPONSE_BYTES, LINE_OVERFLOW,
            BoundedBodyReader.MAX_RESPONSE_BYTES, "SSE response exceeded character limit");
    private static final SseFrameReader.Limits ENDPOINT_LIMITS = new SseFrameReader.Limits(
            MAX_EVENT_BYTES, MAX_ENDPOINT_SCAN_BYTES, "Endpoint event scan exceeded " + MAX_ENDPOINT_SCAN_BYTES + " bytes",
            MAX_ENDPOINT_SCAN_BYTES, "Endpoint event scan exceeded " + MAX_ENDPOINT_SCAN_BYTES + " bytes");

    private SseResponseParser() {}

    public static boolean isEventStream(String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains(EVENT_STREAM_MEDIA_TYPE);
    }

    public static List<String> eventData(String body) {
        List<String> data = new ArrayList<>();
        SseFrameReader frames = SseFrameReader.over(
                new BufferedReader(new StringReader((body == null ? "" : body) + FRAME_TERMINATOR)), RESPONSE_LIMITS);
        try {
            for (String frame = frames.nextFrame(); frame != null; frame = frames.nextFrame()) {
                SseFrame event = SseFrame.parse(frame);
                if (event.hasData()) {
                    data.add(boundedData(event));
                }
            }
        } catch (IOException oversized) {
            return data;
        }
        return data;
    }

    public static SseFrameReader eventFrames(InputStream stream) {
        return SseFrameReader.capturing(stream, EVENT_LIMITS);
    }

    public static RawSseFrame nextDataFrame(SseFrameReader frames) throws IOException {
        RawSseFrame frame;
        while ((frame = frames.nextRawFrame()) != null) {
            SseFrame event = SseFrame.parse(frame.text());
            if (event.hasData()) {
                boundedData(event);
                return frame;
            }
        }
        return null;
    }

    public static String extractJsonRpcResponse(String sseBody) {
        if (sseBody == null || sseBody.isEmpty()) {
            return null;
        }
        try {
            return extractJsonRpcResponse(new BufferedReader(new StringReader(sseBody)));
        } catch (IOException e) {
            return null;
        }
    }

    public static String extractJsonRpcResponse(BufferedReader reader) throws IOException {
        SseFrameReader frames = SseFrameReader.over(reader, EVENT_LIMITS);
        String lastData = null;
        String frame;
        while ((frame = frames.nextFrame()) != null) {
            SseFrame event = SseFrame.parse(frame);
            if (event.isMessage() && event.hasData()) {
                String data = boundedData(event);
                if (isReply(data)) {
                    return data;
                }
                lastData = data;
            }
        }
        return lastData;
    }

    public static String extractJsonRpcResponse(BufferedReader reader, JsonNode expectedId) throws IOException {
        return extractJsonRpcResponse(reader, expectedId, ServerPingAnswerer.ignoring());
    }

    public static String extractJsonRpcResponse(BufferedReader reader, JsonNode expectedId,
                                                ServerPingAnswerer serverRequests) throws IOException {
        ReplyCollector replies = new ReplyCollector(expectedId);
        SseFrameReader frames = SseFrameReader.over(reader, RESPONSE_LIMITS);
        int events = 0;
        String frame;
        while ((frame = frames.nextFrame()) != null) {
            if (++events > MAX_RESPONSE_EVENTS) throw new IOException("SSE response exceeded event limit");
            SseFrame event = SseFrame.parse(frame);
            if (event.isMessage() && completesReply(boundedData(event), replies, serverRequests)) return replies.body();
        }
        return replies.body();
    }

    private static boolean completesReply(String data, ReplyCollector replies, ServerPingAnswerer serverRequests) {
        return !serverRequests.consume(data) && replies.accept(data);
    }

    private static String boundedData(SseFrame event) throws IOException {
        String data = event.hasData() ? event.data() : "";
        if (data.length() > MAX_EVENT_BYTES) {
            throw new IOException("SSE event data exceeded " + MAX_EVENT_BYTES + " bytes");
        }
        return data;
    }

    public static JsonNode expectedReplyId(String body) {
        try {
            JsonNode request = McpObjectMapper.INSTANCE.readTree(body);
            if (request != null && request.isArray()) {
                var ids = McpObjectMapper.INSTANCE.createArrayNode();
                for (JsonNode member : request) {
                    if (!member.isObject() || member.has("id") || !member.path("method").isTextual()) {
                        ids.add(replyId(member));
                    }
                }
                return request.isEmpty() ? com.fasterxml.jackson.databind.node.NullNode.getInstance() : ids;
            }
            JsonNode id = request == null ? null : request.get("id");
            if (id != null && (id.isTextual() || id.isNumber())) return id;
        } catch (IOException invalidRequest) { }
        return com.fasterxml.jackson.databind.node.NullNode.getInstance();
    }

    private static JsonNode replyId(JsonNode request) {
        JsonNode id = request.get("id");
        return id != null && (id.isTextual() || id.isNumber())
                ? id : com.fasterxml.jackson.databind.node.NullNode.getInstance();
    }

    private static final class ReplyCollector {
        private final boolean batch;
        private final boolean anyId;
        private final Map<JsonNode, Integer> pending = new LinkedHashMap<>();
        private final List<JsonNode> received = new ArrayList<>();
        private String singleReply;

        private ReplyCollector(JsonNode expectedId) {
            batch = expectedId != null && expectedId.isArray();
            anyId = expectedId == null;
            if (batch) expectedId.forEach(id -> pending.merge(id, 1, Integer::sum));
            else if (!anyId) pending.put(expectedId, 1);
        }

        private boolean accept(String data) {
            try {
                JsonNode reply = McpObjectMapper.INSTANCE.readTree(data);
                if (batch && reply != null && reply.isArray()) reply.forEach(this::acceptReply);
                else acceptReply(reply);
                if (!batch && !received.isEmpty()) singleReply = data;
            } catch (IOException invalidEvent) { }
            return !received.isEmpty() && pending.isEmpty();
        }

        private void acceptReply(JsonNode reply) {
            if (reply != null && reply.isObject() && reply.has("id") && !reply.has("method")
                    && (reply.has("result") != reply.has("error"))
                    && (anyId || consumeExpectedId(reply.get("id")))) {
                received.add(reply);
            }
        }

        private boolean consumeExpectedId(JsonNode id) {
            Integer count = pending.get(id);
            if (count == null) return false;
            if (count == 1) pending.remove(id);
            else pending.put(id, count - 1);
            return true;
        }

        private String body() {
            if (received.isEmpty()) return null;
            if (!batch) return singleReply;
            return McpObjectMapper.INSTANCE.createArrayNode().addAll(received).toString();
        }
    }

    public static SseFrameReader endpointFrames(InputStream stream) {
        return SseFrameReader.over(stream, ENDPOINT_LIMITS);
    }

    public static String extractEndpointUrl(SseFrameReader frames) throws IOException {
        String frame;
        while ((frame = frames.nextFrame()) != null) {
            SseFrame event = SseFrame.parse(frame);
            if (event.isEvent(ENDPOINT_EVENT) && event.hasData()) {
                return event.data().trim();
            }
        }
        return null;
    }

    private static boolean isReply(String json) {
        try {
            JsonNode node = McpObjectMapper.INSTANCE.readTree(json);
            return node != null && node.isObject() && !node.has("method") && (node.has("result") || node.has("error"));
        } catch (Exception e) {
            return false;
        }
    }
}
