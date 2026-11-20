package com.mcpscanner.proxy;

import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.ProtocolHttpResponse;
import com.mcpscanner.client.ProtocolHttpTransport;
import com.mcpscanner.http.evidence.BodyCapture;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.mcp.BoundedBodyReader;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;

final class RecordingTransport implements ProtocolHttpTransport {

    private final ProtocolHttpTransport delegate;
    private final UpstreamCaptures captures;

    RecordingTransport(ProtocolHttpTransport delegate, UpstreamCaptures captures) {
        this.delegate = delegate;
        this.captures = captures;
    }

    @Override
    public ProtocolHttpResponse send(ProtocolHttpRequest request, Duration timeout)
            throws IOException, InterruptedException {
        Optional<ForwardCapture> capture = captures.current();
        ProtocolHttpResponse response = delegate.send(request, timeout);
        return capture.flatMap(active -> response.wire().map(wire -> recorded(active, request, response, wire)))
                .orElse(response);
    }

    private static ProtocolHttpResponse recorded(ForwardCapture capture, ProtocolHttpRequest request,
                                                 ProtocolHttpResponse response, WireRecord wire) {
        BodyCapture body = new BodyCapture(response.body(), BoundedBodyReader.MAX_RESPONSE_BYTES);
        capture.record(() -> new RecordedExchange(request.body(), body.completing(wire)));
        return response.withBody(body);
    }
}
