package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.evidence.BodyCapture;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.mcp.BoundedBodyReader;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

final class UnstreamingProbeClient implements OutsideBurpClient {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final String CONTENT_TYPE = "Content-Type";
    private static final Set<String> CLIENT_MANAGED_HEADERS = caseInsensitive(
            "Host", "Content-Length", "Connection", "Expect", "Upgrade", "Transfer-Encoding");

    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(CONNECT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private final Duration responseTimeout;
    private final ProbeReplyReader replies;

    UnstreamingProbeClient(Duration responseTimeout) {
        this.responseTimeout = responseTimeout;
        this.replies = new ProbeReplyReader(responseTimeout);
    }

    @Override
    public Optional<HttpRequestResponse> send(HttpRequest request) {
        byte[] body = bodyOf(request);
        return Optional.of(exchange(jdkRequest(request, body), body, request).evidence());
    }

    private WireRecord exchange(java.net.http.HttpRequest jdk, byte[] body, HttpRequest request) {
        try {
            java.net.http.HttpResponse<InputStream> response = client.send(jdk,
                    java.net.http.HttpResponse.BodyHandlers.ofInputStream());
            try (BodyCapture reply = new BodyCapture(response.body(), BoundedBodyReader.MAX_RESPONSE_BYTES)) {
                replies.awaitReply(response.headers().firstValue(CONTENT_TYPE), reply, request);
                return reply.completing(WireRecord.ofJdk(jdk, body, response));
            }
        } catch (IOException unanswered) {
            return WireRecord.unansweredJdk(jdk, body);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return WireRecord.unansweredJdk(jdk, body);
        }
    }

    private java.net.http.HttpRequest jdkRequest(HttpRequest request, byte[] body) {
        java.net.http.HttpRequest.Builder builder = java.net.http.HttpRequest.newBuilder(URI.create(request.url()))
                .timeout(responseTimeout)
                .method(request.method(), publisherOf(body));
        for (HttpHeader header : request.headers()) {
            if (!CLIENT_MANAGED_HEADERS.contains(header.name())) {
                builder.header(header.name(), header.value());
            }
        }
        return builder.build();
    }

    private static byte[] bodyOf(HttpRequest request) {
        return request.body() == null ? new byte[0] : request.body().getBytes();
    }

    private static java.net.http.HttpRequest.BodyPublisher publisherOf(byte[] body) {
        return body.length == 0
                ? java.net.http.HttpRequest.BodyPublishers.noBody()
                : java.net.http.HttpRequest.BodyPublishers.ofByteArray(body);
    }

    private static Set<String> caseInsensitive(String... names) {
        Set<String> set = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        set.addAll(List.of(names));
        return set;
    }
}
