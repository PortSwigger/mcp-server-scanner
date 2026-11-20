package com.mcpscanner.proxy;

import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.SseFrameReader;
import com.mcpscanner.mcp.SseResponseParser;
import com.mcpscanner.core.protocol.McpSse;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpResponse;

final class SseStreamOpening {

    private SseStreamOpening() {}

    static ProxyResponse refusal(HttpResponse<InputStream> response) {
        String body = "";
        try (InputStream stream = response.body()) {
            if (stream != null) {
                body = BoundedBodyReader.readUtf8(stream);
            }
        } catch (IOException ignored) {
        }
        return new ProxyResponse(response.statusCode(), "application/json", body,
                SseRequestHeaders.challenge(response.headers()));
    }

    static String messageEndpoint(SseFrameReader frames, URI reachedSseUrl) throws IOException {
        String path = SseResponseParser.extractEndpointUrl(frames);
        if (path == null) {
            throw new IOException("SSE stream closed without sending endpoint event");
        }
        String endpointPath = McpSse.endpoint(reachedSseUrl.toString(), "event: endpoint\ndata: " + path + "\n\n",
                BoundedBodyReader.MAX_RESPONSE_BYTES);
        return reachedSseUrl.resolve(endpointPath).toString();
    }
}
