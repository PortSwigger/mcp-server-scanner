package com.mcpscanner.proxy;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.client.JdkProtocolHttpTransport;
import com.mcpscanner.client.McpHttpClients;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.ProtocolHttpResponse;
import com.mcpscanner.client.ProtocolHttpTransport;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class UpstreamWireEvidenceTest {

    private static final String REQUEST_BODY = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\"}";
    private static final String REPLY = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\r\n";

    private final UpstreamCaptures captures = new UpstreamCaptures();
    private final ProtocolHttpTransport upstream = new SentinelStrippingTransport(
            captures.recording(new JdkProtocolHttpTransport(McpHttpClients.upstream())));
    private HttpServer server;

    @BeforeEach
    void startServer() throws IOException {
        MontoyaTestFactory.install();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/fixed", exchange -> reply(exchange, REPLY.length()));
        server.createContext("/chunked", exchange -> reply(exchange, 0));
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void theRecordedRequestIsWhatTheTargetReceivedWithItsCredentialAndWithoutSentinels() throws Exception {
        HttpRequestResponse evidence = forward("/fixed");

        String request = text(evidence.request().toByteArray().getBytes());
        assertThat(request).startsWith("POST /fixed HTTP/1.1\r\nContent-Length: " + REQUEST_BODY.length() + "\r\n"
                        + "Host: 127.0.0.1:" + server.getAddress().getPort() + "\r\nUser-Agent: Java-http-client/")
                .contains("\r\nAuthorization: Bearer real-token\r\n")
                .doesNotContainIgnoringCase("X-Mcp-Scanner-")
                .endsWith("\r\n\r\n" + REQUEST_BODY);
    }

    @Test
    void theRecordedResponseKeepsTheReasonEveryRepeatedHeaderAndTheExactBody() throws Exception {
        HttpRequestResponse evidence = forward("/fixed");

        String response = text(evidence.response().toByteArray().getBytes());
        assertThat(response).startsWith("HTTP/1.1 200 OK\r\n")
                .contains("\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n", "\r\ncontent-length: " + REPLY.length() + "\r\n")
                .endsWith("\r\n\r\n" + REPLY);
    }

    @Test
    void aResponseWithoutContentLengthIsNotGivenOne() throws Exception {
        HttpRequestResponse evidence = forward("/chunked");

        String response = text(evidence.response().toByteArray().getBytes());
        assertThat(response).doesNotContainIgnoringCase("content-length").endsWith("\r\n\r\n" + REPLY);
    }

    private HttpRequestResponse forward(String path) throws Exception {
        try (ForwardCapture capture = captures.open()) {
            try (ProtocolHttpResponse response = upstream.send(post(path), Duration.ofSeconds(5))) {
                assertThat(new String(response.body().readAllBytes(), StandardCharsets.UTF_8)).isEqualTo(REPLY);
            }
            return capture.chosenFor(REQUEST_BODY).orElseThrow().evidence().get(0);
        }
    }

    private ProtocolHttpRequest post(String path) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", "Bearer real-token");
        headers.put(ScannerSentinels.IDENTITY_HEADER, "primary");
        headers.put(ScannerSentinels.KEEP_SESSION_HEADER, ScannerSentinels.SENTINEL_VALUE);
        return new ProtocolHttpRequest(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path),
                "POST", headers, REQUEST_BODY);
    }

    private static void reply(HttpExchange exchange, long length) throws IOException {
        exchange.getRequestBody().readAllBytes();
        exchange.getResponseHeaders().add("Set-Cookie", "a=1");
        exchange.getResponseHeaders().add("Set-Cookie", "b=2");
        exchange.sendResponseHeaders(200, length);
        try (OutputStream body = exchange.getResponseBody()) {
            body.write(REPLY.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }
}
