package com.mcpscanner.integration;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end proof that the Streamable-HTTP scanner handshake, driven through the JDK
 * {@link HttpClient}, establishes a real session against the live Python test-server: a
 * server-minted {@code Mcp-Session-Id} is captured into {@code scannerHeaders}, a protocol
 * version is negotiated, and {@code resolvedEndpoint} is set.
 *
 * <p>The handshake reads the initialize reply incrementally so it can lift the JSON-RPC reply out
 * of the first SSE event without waiting for the stream to close — the keep-alive case. The
 * test-server closes the stream after the first event, so this IT cannot catch that regression
 * (the unit test {@code negotiateProtocolVersion_doesNotHangOnSseKeepAlive} does); it proves the
 * end-to-end wire dance + header casing against a real server.
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class StreamableHandshakeIT {

    @Mock
    private Logging logging;

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void noAuthHandshakeEstablishesRealSession() throws Exception {
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer("--auth", "none")) {
            McpScannerSession session = newSession();
            String endpoint = McpCheckItSupport.mcpEndpoint(server.port());

            session.connect(new McpServerConfig(endpoint, TransportType.STREAMABLE_HTTP, new NoAuthStrategy()));

            assertThat(session.resolvedEndpoint())
                    .as("handshake resolves the streamable endpoint as-is")
                    .isEqualTo(endpoint);
            assertThat(session.scannerHeaders())
                    .as("server-minted Mcp-Session-Id is captured via the JDK HttpClient handshake")
                    .containsKey("Mcp-Session-Id");
            assertThat(session.scannerHeaders().get("Mcp-Session-Id"))
                    .as("session id is a non-blank server value")
                    .isNotBlank();
            assertThat(session.scannerHeaders())
                    .as("a protocol version is negotiated from the initialize reply")
                    .containsKey("MCP-Protocol-Version");
            assertThat(session.scannerHeaders().get("MCP-Protocol-Version")).isNotBlank();

            session.disconnect();
        }
    }

    @Test
    void authenticatedHandshakeSucceedsWithMintedToken() throws Exception {
        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "oauth", "--oauth-test-mint-endpoint")) {
            String token = McpCheckItSupport.mintTestToken(server.port());
            McpScannerSession session = newSession();
            String endpoint = McpCheckItSupport.mcpEndpoint(server.port());

            session.connect(new McpServerConfig(
                    endpoint, TransportType.STREAMABLE_HTTP, new BearerTokenAuthStrategy(token)));

            assertThat(session.scannerHeaders())
                    .as("authenticated handshake captures a real session id")
                    .containsKey("Mcp-Session-Id");
            assertThat(session.scannerHeaders().get("Mcp-Session-Id")).isNotBlank();
            assertThat(session.scannerHeaders())
                    .containsEntry("Authorization", "Bearer " + token)
                    .containsKey("MCP-Protocol-Version");

            session.disconnect();
        }
    }

    private McpScannerSession newSession() {
        // Mirror production wiring: a JDK HttpClient with Redirect.NORMAL (set in McpClientManager).
        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        return new McpScannerSession(httpClient, logging, new McpEventLog(null));
    }
}
