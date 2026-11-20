package com.mcpscanner.checks.shared.stream;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.HeaderMutation;
import com.mcpscanner.mcp.ScannerSentinels;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class JdkStreamOpener implements StreamOpener {

    private static final Duration GRACE = Duration.ofSeconds(1);

    private final StreamLimits limits;
    private final UnreachableStreamWarnings warnings;
    private final HttpClient client;

    public JdkStreamOpener(McpEventLog log) {
        this(StreamLimits.standard(), log);
    }

    public JdkStreamOpener(StreamLimits limits) {
        this(limits, McpEventLog.noop());
    }

    public JdkStreamOpener(StreamLimits limits, McpEventLog log) {
        this.limits = limits;
        this.warnings = new UnreachableStreamWarnings(log);
        this.client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(limits.headerTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public StreamOpening open(HttpRequest request) {
        HttpRequest sent = HeaderMutation.apply(request, ScannerSentinels.ALL, Map.of());
        byte[] body = bodyOf(sent);
        try {
            return open(sent, toJdk(sent, body), body);
        } catch (IllegalArgumentException unsendable) {
            return StreamOpening.unsent(sent);
        }
    }

    private StreamOpening open(HttpRequest sent, java.net.http.HttpRequest jdk, byte[] body) {
        StreamPrefix prefix = new StreamPrefix(limits.maxPrefixBytes());
        CompletableFuture<HttpResponse<StreamPrefix>> pending = null;
        try {
            pending = client.sendAsync(jdk, info -> prefix);
            HttpResponse<StreamPrefix> response = pending.get(headerWait(), TimeUnit.MILLISECONDS);
            StreamPrefix.Read read = prefix.await(limits.holdWindow());
            return StreamOpening.answered(WireRecord.ofJdk(jdk, body, response).withBody(read.bytes(), read.capped()),
                    !read.ended());
        } catch (ExecutionException failed) {
            warnings.note(sent, failed.getCause());
            return unanswered(jdk, body);
        } catch (TimeoutException unanswered) {
            return unanswered(jdk, body);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return unanswered(jdk, body);
        } finally {
            prefix.cancel();
            if (pending != null) {
                pending.cancel(true);
            }
        }
    }

    private static StreamOpening unanswered(java.net.http.HttpRequest jdk, byte[] body) {
        return StreamOpening.unanswered(WireRecord.unansweredJdk(jdk, body));
    }

    private long headerWait() {
        return limits.headerTimeout().plus(GRACE).toMillis();
    }

    private java.net.http.HttpRequest toJdk(HttpRequest request, byte[] body) {
        java.net.http.HttpRequest.Builder builder = java.net.http.HttpRequest.newBuilder(URI.create(request.url()))
                .timeout(limits.headerTimeout())
                .method(request.method(), publisherOf(body));
        request.headers().forEach(header -> addPermitted(builder, header));
        return builder.build();
    }

    private static byte[] bodyOf(HttpRequest request) {
        String body = request.bodyToString();
        return body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
    }

    private static java.net.http.HttpRequest.BodyPublisher publisherOf(byte[] body) {
        return body.length == 0 ? java.net.http.HttpRequest.BodyPublishers.noBody()
                : java.net.http.HttpRequest.BodyPublishers.ofByteArray(body);
    }

    private static void addPermitted(java.net.http.HttpRequest.Builder builder, HttpHeader header) {
        try {
            builder.header(header.name(), header.value());
        } catch (IllegalArgumentException headerTheClientSetsItself) {
            return;
        }
    }
}
