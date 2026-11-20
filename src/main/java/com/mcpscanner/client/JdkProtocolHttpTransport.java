package com.mcpscanner.client;

import com.mcpscanner.http.evidence.WireRecord;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

public final class JdkProtocolHttpTransport implements ProtocolHttpTransport {

    private final HttpClient client;

    public JdkProtocolHttpTransport(HttpClient client) {
        this.client = client;
    }

    @Override
    public ProtocolHttpResponse send(ProtocolHttpRequest request, Duration timeout)
            throws IOException, InterruptedException {
        HttpRequest jdkRequest = toJdkRequest(request, timeout);
        HttpResponse<InputStream> response = client.send(jdkRequest, HttpResponse.BodyHandlers.ofInputStream());
        return new ProtocolHttpResponse(response.statusCode(), response.headers().map(), response.body(),
                response.uri(), Optional.of(WireRecord.ofJdk(jdkRequest, bodyBytes(request), response)));
    }

    private static HttpRequest toJdkRequest(ProtocolHttpRequest request, Duration timeout) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(request.uri())
                .timeout(timeout)
                .method(request.method(), bodyOf(request));
        request.headers().forEach(builder::header);
        return builder.build();
    }

    private static HttpRequest.BodyPublisher bodyOf(ProtocolHttpRequest request) {
        return request.hasBody()
                ? HttpRequest.BodyPublishers.ofString(request.body())
                : HttpRequest.BodyPublishers.noBody();
    }

    private static byte[] bodyBytes(ProtocolHttpRequest request) {
        return request.hasBody() ? request.body().getBytes(StandardCharsets.UTF_8) : new byte[0];
    }
}
