package com.mcpscanner.integration;

import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@EnabledIfEnvironmentVariable(named = "MCP_OAUTH_IT", matches = "1")
class OAuthDiscoveryIT {

    private static final String HOST = "127.0.0.1";
    private static final Duration BOOT_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration POLL_INTERVAL = Duration.ofMillis(200);
    private static final Duration SHUTDOWN_GRACE = Duration.ofSeconds(5);

    // The loopback test-server this IT boots is trusted by construction, so we pass an
    // always-allow gate. The zero-arg defaultInstance() wires an always-deny confirmer that
    // (correctly) refuses loopback under prompt-less operation; production instead wires the
    // interactive Swing confirmer gate, which prompts rather than auto-denies.
    private static final SuspiciousDestinationGate ALLOW_LOOPBACK =
            (url, purpose) -> SuspiciousDestinationGate.Decision.allow();

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void asOnlyMode_discoveryFallsThroughToAsWellKnown() throws Exception {
        int port = findFreePort();
        Process server = startTestServer(port);
        try {
            waitForReadiness(asWellKnownUrl(port));

            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient());
            DiscoveredMetadata result = OAuthMetadataDiscoverer
                    .defaultInstance(realHttp, null, ALLOW_LOOPBACK)
                    .discover(URI.create("http://" + HOST + ":" + port + "/mcp"));

            assertThat(result.source()).isEqualTo(DiscoverySource.AS_WELL_KNOWN);
            assertThat(result.issuer()).isNotNull();
            assertThat(result.asMetadata()).isNotNull();
        } finally {
            shutdown(server);
        }
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static Process startTestServer(int port) throws IOException {
        List<String> command = List.of(
                "uv", "run", "--no-sync", "mcp-test-server",
                "--auth", "oauth",
                "--oauth-discovery", "as-only",
                "--host", HOST,
                "--port", String.valueOf(port));
        return new ProcessBuilder(command)
                .directory(new File("test-server"))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
    }

    private static URI asWellKnownUrl(int port) {
        return URI.create("http://" + HOST + ":" + port + "/.well-known/oauth-authorization-server");
    }

    private static void waitForReadiness(URI url) {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder(url)
                .timeout(Duration.ofSeconds(2))
                .GET()
                .build();
        await().atMost(BOOT_TIMEOUT).pollInterval(POLL_INTERVAL).until(() -> {
            try {
                HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
                return response.statusCode() == 200;
            } catch (IOException ignored) {
                return false;
            }
        });
    }

    private static void shutdown(Process process) throws InterruptedException {
        process.destroy();
        if (!process.waitFor(SHUTDOWN_GRACE.toSeconds(), TimeUnit.SECONDS)) {
            process.destroyForcibly();
        }
    }
}
