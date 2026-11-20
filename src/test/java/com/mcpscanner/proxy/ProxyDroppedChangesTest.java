package com.mcpscanner.proxy;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.client.ConnectedEndpoint;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.FramedOperation;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ProxyDroppedChangesTest {

    private static final String ENDPOINT = "http://127.0.0.1:3001/mcp";
    private static final String ISSUED_SESSION = "scanner-session";
    private static final String CALL = "{\"jsonrpc\":\"2.0\",\"id\":32,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"slow\",\"arguments\":{\"duration\":10}}}";

    private HttpRequest scanned;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        scanned = HttpRequest.httpRequestFromUrl(ENDPOINT).withMethod("POST")
                .withHeader(McpHeaders.METHOD, "tools/call")
                .withHeader(McpHeaders.NAME, "slow")
                .withHeader(McpHeaders.PROTOCOL_VERSION, "2026-07-28")
                .withHeader(ScannerSentinels.AUDIT_CAPABILITY_HEADER, "capability")
                .withHeader(ScannerSentinels.FRAMED_OPERATION_HEADER, FramedOperation.encode(Map.of(
                        McpHeaders.METHOD, "tools/call", McpHeaders.NAME, "slow",
                        McpHeaders.PROTOCOL_VERSION, "2026-07-28")))
                .withBody(CALL);
    }

    @Test
    void theProxyDropsAPayloadInTheJsonRpcId() {
        assertThat(dropped(scanned, scanned.withBody(CALL.replace("\"id\":32", "\"id\":\"32;payload\"")))).isTrue();
    }

    @Test
    void theProxyDropsAPayloadInTheUrl() {
        assertThat(dropped(scanned, scanned.withPath("/mcp?payload=1"))).isTrue();
    }

    @Test
    void theProxyDropsAPayloadInATransportHeader() {
        assertThat(dropped(scanned, scanned.withHeader("Accept", "payload"))).isTrue();
    }

    @Test
    void theProxySendsAPayloadInAnOperationHeaderToTheServer() {
        assertThat(dropped(scanned, scanned.withHeader(McpHeaders.NAME, "slow;payload"))).isFalse();
        assertThat(dropped(scanned, scanned.withHeader(McpHeaders.METHOD, "tools/call;payload"))).isFalse();
        assertThat(dropped(scanned, scanned.withHeader(McpHeaders.PROTOCOL_VERSION, "payload"))).isFalse();
    }

    @Test
    void theProxySendsAnOperationHeaderPayloadOnARequestTheScannerDidNotFrameToTheServer() {
        HttpRequest unframed = scanned.withRemovedHeader(ScannerSentinels.FRAMED_OPERATION_HEADER);

        assertThat(dropped(unframed, unframed.withHeader(McpHeaders.NAME, "slow;payload"))).isFalse();
    }

    @Test
    void theProxyForwardsAPayloadInAnArgumentOrAForwardedHeader() {
        assertThat(dropped(scanned, scanned.withBody(CALL.replace("10", "\"10;payload\"")))).isFalse();
        assertThat(dropped(scanned, scanned.withAddedHeader("Referer", "https://example.com/payload"))).isFalse();
    }

    @Test
    void aRequestSentStraightToTheServerKeepsEveryPayload() {
        HttpRequest direct = scanned.withRemovedHeader(ScannerSentinels.AUDIT_CAPABILITY_HEADER);

        assertThat(dropped(direct, direct.withPath("/mcp?payload=1"))).isFalse();
    }

    @Test
    void aRequestTheProxyForwardsWithItsOwnHeadersKeepsItsHeaderPayloads() {
        HttpRequest unmanaged = scanned.withAddedHeader(ScannerSentinels.STRIP_AUTH_HEADER,
                ScannerSentinels.SENTINEL_VALUE);

        assertThat(dropped(unmanaged, unmanaged.withHeader(McpHeaders.NAME, "slow;payload"))).isFalse();
    }

    @Test
    void aRequestOnTheScannersOwnSessionLosesItsJsonRpcIdPayload() {
        HttpRequest onSession = scanned.withAddedHeader(McpHeaders.SESSION_ID, ISSUED_SESSION);

        assertThat(dropped(onSession, onSession.withBody(CALL.replace("\"id\":32", "\"id\":\"payload\"")))).isTrue();
    }

    @Test
    void aRequestPresentingAnotherSessionKeepsItsHeaderPayloads() {
        HttpRequest foreign = scanned.withAddedHeader(McpHeaders.SESSION_ID, "foreign-session");

        assertThat(dropped(foreign, foreign.withHeader(McpHeaders.PROTOCOL_VERSION, "payload"))).isFalse();
    }

    @Test
    void aPayloadInTheSessionIdReachesTheServerAsAPresentedSession() {
        HttpRequest onSession = scanned.withAddedHeader(McpHeaders.SESSION_ID, ISSUED_SESSION);

        assertThat(dropped(onSession, onSession.withHeader(McpHeaders.SESSION_ID, "payload"))).isFalse();
    }

    @Test
    void aPayloadInTheUrlPathLeavesTheProxyAndReachesTheServer() {
        assertThat(dropped(scanned, scanned.withPath("/mcp/..%2fpayload"))).isFalse();
    }

    @Test
    void aPayloadThatStripsTheScannersCredentialsReachesTheServerUnmanaged() {
        assertThat(dropped(scanned, scanned.withAddedHeader(ScannerSentinels.STRIP_AUTH_HEADER,
                ScannerSentinels.SENTINEL_VALUE).withHeader(McpHeaders.NAME, "slow;payload"))).isFalse();
    }

    @Test
    void aRequestOverTheLegacySseTransportKeepsItsHeaderPayloads() {
        assertThat(new ProxyDroppedChanges(endpoint(TransportType.SSE), ISSUED_SESSION::equals)
                .dropsEveryChange(scanned, scanned.withHeader(McpHeaders.NAME, "slow;payload"))).isFalse();
    }

    private static boolean dropped(HttpRequest base, HttpRequest altered) {
        return new ProxyDroppedChanges(endpoint(TransportType.STREAMABLE_HTTP), ISSUED_SESSION::equals)
                .dropsEveryChange(base, altered);
    }

    private static ConnectedEndpoint endpoint(TransportType transport) {
        return new ConnectedEndpoint() {
            @Override
            public TransportType transportType() {
                return transport;
            }

            @Override
            public String resolvedEndpoint() {
                return ENDPOINT;
            }
        };
    }
}
