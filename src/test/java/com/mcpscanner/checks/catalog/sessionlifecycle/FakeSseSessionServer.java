package com.mcpscanner.checks.catalog.sessionlifecycle;

import com.mcpscanner.mcp.SseProbeStream;
import com.mcpscanner.mcp.SseProbeStreams;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcEnvelope;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.ProtocolHttpResponse;
import com.mcpscanner.testutil.FakeMcpServer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

final class FakeSseSessionServer implements SseProbeStreams {

    static final String LIVE_SESSION = "live-sse-session";
    static final String QUERY_MESSAGE_URL = "http://target.test/messages/?session_id=";
    static final String PATH_MESSAGE_URL = "http://target.test/mcp/sessions/";

    final List<String> issued = new ArrayList<>();
    final List<String> closed = new ArrayList<>();
    final List<ProtocolHttpRequest> posts = new ArrayList<>();
    private final Map<String, BlockingQueue<String>> streams = new ConcurrentHashMap<>();
    private String latest;
    Supplier<String> ids;
    String messageUrl = QUERY_MESSAGE_URL;
    boolean fixedRoute;
    boolean encodeIds;

    @Override
    public synchronized SseProbeStream open(Map<String, String> headers) {
        String id = ids.get();
        issued.add(id);
        BlockingQueue<String> events = new LinkedBlockingQueue<>();
        streams.put(id, events);
        latest = id;
        return new SseProbeStream() {
            @Override
            public String messageUrl() {
                return fixedRoute ? messageUrl : messageUrl + (encodeIds ? URLEncoder.encode(id, StandardCharsets.UTF_8) : id);
            }

            @Override
            public String nextEvent() {
                try {
                    return events.poll(2, TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }

            @Override
            public void beginReplyWait() {
            }

            @Override
            public void close() {
                closed.add(id);
                streams.remove(id);
            }
        };
    }

    synchronized Optional<ProtocolHttpResponse> respond(ProtocolHttpRequest request) {
        posts.add(request);
        String url = request.uri().toString();
        String session = URLDecoder.decode(url.substring(url.lastIndexOf(url.contains("session_id=") ? "=" : "/") + 1),
                StandardCharsets.UTF_8);
        if (LIVE_SESSION.equals(session)) {
            return Optional.of(FakeMcpServer.respond(request));
        }
        BlockingQueue<String> stream = streams.get(fixedRoute ? latest : session);
        if (stream == null) {
            return Optional.of(FakeMcpServer.exchange(request, 404, Map.of(), "Could not find session"));
        }
        if (JsonRpcEnvelope.of(request.body()).id().isPresent()) {
            stream.add("event: message\ndata: " + body(FakeMcpServer.respond(request)) + "\n\n");
        }
        return Optional.of(FakeMcpServer.exchange(request, 202, Map.of(), "Accepted"));
    }

    private static String body(ProtocolHttpResponse response) {
        try {
            return new String(response.body().readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException failed) {
            throw new UncheckedIOException(failed);
        }
    }
}
