package com.mcpscanner.http.evidence;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class JdkWireTest {

    private static final String OK_REPLY = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    private static final String JSON = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

    private LoopbackWireCapture wire;

    @BeforeEach
    void openLoopback() throws Exception {
        wire = new LoopbackWireCapture();
    }

    @AfterEach
    void closeLoopback() throws Exception {
        wire.close();
    }

    @Test
    void aBodylessGetIsRenderedByteForByteAsTheClientWroteIt() throws Exception {
        HttpRequest get = builder("/mcp?session=1").method("GET", HttpRequest.BodyPublishers.noBody()).build();

        assertRenderedAsSent(get, new byte[0]);
    }

    @Test
    void aBuilderGetWithoutAPublisherIsRenderedByteForByteAsTheClientWroteIt() throws Exception {
        HttpRequest get = builder("/mcp").GET().build();

        assertRenderedAsSent(get, new byte[0]);
    }

    @Test
    void aJsonPostWithCredentialsCookiesAndUnorderedHeadersIsRenderedByteForByteAsTheClientWroteIt()
            throws Exception {
        HttpRequest post = builder("/mcp")
                .header("Zeta", "last")
                .header("Mcp-Session-Id", "s-1")
                .header("authorization", "Bearer secret-token")
                .header("Cookie", "a=1")
                .header("Accept", "application/json, text/event-stream")
                .header("X-Repeated", "one")
                .header("x-repeated", "two")
                .header("cookie", "b=2")
                .header("Content-Type", "application/json")
                .method("POST", HttpRequest.BodyPublishers.ofString(JSON))
                .build();

        String rendered = assertRenderedAsSent(post, JSON.getBytes(StandardCharsets.UTF_8));

        assertThat(rendered).contains("authorization: Bearer secret-token\r\n", "Cookie: a=1; b=2\r\n",
                "Host: 127.0.0.1:", "User-Agent: Java-http-client/", "Content-Length: " + JSON.length() + "\r\n");
    }

    @Test
    void aCallerUserAgentReplacesTheClientDefault() throws Exception {
        HttpRequest post = builder("/mcp").header("User-Agent", "scanner/1")
                .method("POST", HttpRequest.BodyPublishers.ofString(JSON)).build();

        String rendered = assertRenderedAsSent(post, JSON.getBytes(StandardCharsets.UTF_8));

        assertThat(rendered).contains("User-Agent: scanner/1\r\n").doesNotContain("Java-http-client");
    }

    @Test
    void aCallerHostHeaderAllowedByTheJvmReplacesTheClientHost() throws Exception {
        HttpRequest get = builder("/sse").header("Host", "127.0.0.1:" + wire.uri("/").getPort())
                .header("Accept", "text/event-stream").GET().build();

        String rendered = assertRenderedAsSent(get, new byte[0]);

        assertThat(rendered.split("\r\nHost: ", -1)).hasSize(2);
    }

    @Test
    void aNonAsciiPathIsPercentEncodedAsTheClientEncodesIt() throws Exception {
        HttpRequest delete = builder("/café/mcp?q=ü").method("DELETE", HttpRequest.BodyPublishers.noBody())
                .build();

        assertRenderedAsSent(delete, new byte[0]);
    }

    @Test
    void theResponseHeadHasTheStatusReasonAndEveryHeaderValueOnItsOwnLineWithoutAnAddedLength() throws Exception {
        String reply = "HTTP/1.1 202 Accepted\r\nX-B: 1\r\nset-cookie: a=1\r\nSet-Cookie: b=2\r\n"
                + "Connection: close\r\n\r\n";
        LoopbackWireCapture.Captured captured = wire.send(builder("/mcp").GET().build(), reply);

        String head = new String(JdkWire.responseHead(captured.response()), StandardCharsets.ISO_8859_1);

        assertThat(head).isEqualTo("HTTP/1.1 202 Accepted\r\nconnection: close\r\nset-cookie: a=1\r\n"
                + "set-cookie: b=2\r\nx-b: 1\r\n\r\n");
    }

    private String assertRenderedAsSent(HttpRequest request, byte[] body) throws Exception {
        LoopbackWireCapture.Captured captured = wire.send(request, OK_REPLY);

        byte[] rendered = JdkWire.request(request, body);

        assertThat(new String(rendered, StandardCharsets.ISO_8859_1)).isEqualTo(captured.receivedText());
        assertThat(rendered).isEqualTo(captured.received());
        return captured.receivedText();
    }

    private HttpRequest.Builder builder(String pathAndQuery) {
        return HttpRequest.newBuilder(wire.uri(pathAndQuery)).timeout(Duration.ofSeconds(10));
    }
}
