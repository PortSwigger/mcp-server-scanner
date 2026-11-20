package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

@Timeout(30)
class LegacySseWireEvidenceTest {

    private final IsolatedCatalogDiscovery discovery = new IsolatedCatalogDiscovery(McpEventLog.noop(),
            ClientIdentityProvider.defaults(), new JdkProtocolHttpTransport(McpHttpClients.upstream()),
            ScannerSessionSettings.defaults());
    private RawLegacySseServer server;

    @BeforeEach
    void start() throws IOException {
        MontoyaTestFactory.install();
        server = new RawLegacySseServer();
    }

    @AfterEach
    void stop() throws IOException {
        server.close();
    }

    @Test
    void theToolsListPostIsEvidencedByTheBytesTheServerReceivedAndItsRealReply() {
        HttpRequestResponse post = recordedToolsList().get(0);

        assertThat(post.request().toByteArray().getBytes()).isEqualTo(server.receivedStartingWith("POST "));
        assertThat(text(post.request().toByteArray())).contains("Authorization: Bearer bob\r\n", "Host: 127.0.0.1:",
                "User-Agent: Java-http-client/", "Content-Length: ").doesNotContainIgnoringCase("X-Mcp-Scanner-");
        assertThat(text(post.response().toByteArray())).startsWith("HTTP/1.1 202 Accepted\r\n")
                .contains("set-cookie: a=1\r\nset-cookie: b=2\r\n").endsWith("\r\n\r\nAccepted");
    }

    @Test
    void theStreamIsEvidencedByTheGetTheServerReceivedItsRealHeadAndTheRawEventThatAnswered() {
        HttpRequestResponse stream = recordedToolsList().get(1);

        assertThat(stream.request().toByteArray().getBytes()).isEqualTo(server.receivedStartingWith("GET "));
        assertThat(text(stream.request().toByteArray())).contains("Authorization: Bearer bob\r\n", "Host: 127.0.0.1:",
                "User-Agent: Java-http-client/");
        assertThat(text(stream.response().toByteArray())).startsWith("HTTP/1.1 200 OK\r\n")
                .contains("content-type: text/event-stream\r\n", "x-stream: one\r\nx-stream: two\r\n");
        assertThat(stream.response().body().getBytes())
                .isEqualTo(server.toolsListEvent().getBytes(StandardCharsets.UTF_8));
    }

    private java.util.List<HttpRequestResponse> recordedToolsList() {
        RecordedCatalog recorded = discovery.discoverRecorded(new McpServerConfig(server.endpoint(),
                TransportType.SSE, new BearerTokenAuthStrategy("bob")));
        assertThat(recorded.catalog().tools()).extracting(McpToolDefinition::name)
                .containsExactly(RawLegacySseServer.TOOL);
        assertThat(recorded.toolsList()).hasSize(2);
        return recorded.toolsList();
    }

    private static String text(burp.api.montoya.core.ByteArray bytes) {
        return new String(bytes.getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
    }
}
