package com.mcpscanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import com.mcpscanner.scan.ArgumentPath;
import com.mcpscanner.scan.field.AddedArgumentRegistry;
import com.mcpscanner.scan.field.MetaEnvelopeRegistry;
import com.mcpscanner.testutil.BurpArgumentPoint;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScannedLeavesTest {

    private static final String PROBE_BODY = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":"
            + "{\"name\":\"t\",\"arguments\":{\"url\":\"http://x\",\"filter\":{\"ref\":\"abc\"}}}}";

    private static final String CALL_WITH_META = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"t\",\"arguments\":{\"url\":\"http://x\"},"
            + "\"_meta\":{\"progressToken\":\"p\"}}}";

    private final AddedArgumentRegistry registry = new AddedArgumentRegistry();
    private final MetaEnvelopeRegistry envelopes = new MetaEnvelopeRegistry();
    private final List<HttpRequest> comparedWithBase = new ArrayList<>();
    private boolean proxyDrops = true;
    private final ScannedLeaves probeCalls = new ScannedLeaves(registry, envelopes, (scanned, marked) -> {
        comparedWithBase.add(marked);
        return proxyDrops;
    });
    private HttpRequestResponse base;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        registry.record(PROBE_BODY, ArgumentPath.of("filter", "ref"));
        base = baseWith(PROBE_BODY);
    }

    @Test
    void theRegisteredBodyIsRecognisedAsAProbeCall() {
        assertThat(probeCalls.include(base)).isTrue();
    }

    @Test
    void aBodyTheRegistryNeverRecordedIsNotAProbeCall() {
        assertThat(probeCalls.include(baseWith(PROBE_BODY.replace("abc", "other")))).isFalse();
    }

    @Test
    void aBurpNativeInsertionPointAtTheAddedLeafMayBeFuzzed() {
        assertThat(probeCalls.fuzzesAddedLeaf(base, nativePointAt("filter", "ref"))).isTrue();
    }

    @Test
    void aBurpNativeInsertionPointAtABaseScalarIsLeftToTheBaseCall() {
        assertThat(probeCalls.fuzzesAddedLeaf(base, nativePointAt("url"))).isFalse();
    }

    @Test
    void anInsertionPointThatDoesNotChangeTheBodyIsLeftToTheBaseCall() {
        assertThat(probeCalls.fuzzesAddedLeaf(base, headerPoint())).isFalse();
    }

    @Test
    void aBurpNativeInsertionPointInAPassengersMetaEnvelopeIsLeftToTheCarrier() {
        envelopes.hold(CALL_WITH_META, MetaEnvelopeRegistry.Role.PASSENGER);
        HttpRequestResponse passenger = baseWith(CALL_WITH_META);

        assertThat(probeCalls.isPassengerMetaEnvelopePoint(passenger,
                new BurpArgumentPoint(passenger.request(), "_meta", "progressToken"))).isTrue();
    }

    @Test
    void aPassengersArgumentsAndHeadersAreStillFuzzed() {
        envelopes.hold(CALL_WITH_META, MetaEnvelopeRegistry.Role.PASSENGER);
        HttpRequestResponse passenger = baseWith(CALL_WITH_META);
        base = passenger;

        assertThat(probeCalls.isPassengerMetaEnvelopePoint(passenger,
                new BurpArgumentPoint(passenger.request(), "arguments", "url"))).isFalse();
        assertThat(probeCalls.isPassengerMetaEnvelopePoint(passenger, headerPoint())).isFalse();
    }

    @Test
    void theCarrierAndRequestsNoScanHoldsKeepTheirMetaEnvelope() {
        HttpRequestResponse unknown = baseWith(CALL_WITH_META);
        assertThat(probeCalls.isPassengerMetaEnvelopePoint(unknown,
                new BurpArgumentPoint(unknown.request(), "_meta", "progressToken"))).isFalse();

        envelopes.hold(CALL_WITH_META, MetaEnvelopeRegistry.Role.CARRIER);
        assertThat(probeCalls.isPassengerMetaEnvelopePoint(unknown,
                new BurpArgumentPoint(unknown.request(), "_meta", "progressToken"))).isFalse();
    }

    @Test
    void aPointWhosePayloadBreaksThePassengersJsonIsStillFuzzed() {
        envelopes.hold(CALL_WITH_META, MetaEnvelopeRegistry.Role.PASSENGER);
        HttpRequestResponse passenger = baseWith(CALL_WITH_META);

        assertThat(probeCalls.isPassengerMetaEnvelopePoint(passenger,
                bodyPoint(passenger, CALL_WITH_META.replace("\"p\"}}}", "\"MARK")))).isFalse();
    }

    @Test
    void aPointChangingAMetaLeafAndAnArgumentTogetherIsStillFuzzed() {
        envelopes.hold(CALL_WITH_META, MetaEnvelopeRegistry.Role.PASSENGER);
        HttpRequestResponse passenger = baseWith(CALL_WITH_META);

        assertThat(probeCalls.isPassengerMetaEnvelopePoint(passenger, bodyPoint(passenger,
                CALL_WITH_META.replace("http://x", "m").replace("\"p\"", "\"m\"")))).isFalse();
    }

    @Test
    void aPointWhoseMarkedRequestTheProxyForwardsUnchangedFuzzesOnlyWhatTheProxyDrops() {
        assertThat(probeCalls.fuzzesOnlyWhatTheProxyDrops(base, headerPoint())).isTrue();
        assertThat(comparedWithBase).singleElement()
                .satisfies(marked -> assertThat(marked.headerValue("X-Probe")).isNotBlank());
    }

    @Test
    void aPointWhosePayloadTheProxyForwardsIsStillFuzzed() {
        proxyDrops = false;

        assertThat(probeCalls.fuzzesOnlyWhatTheProxyDrops(base, nativePointAt("url"))).isFalse();
    }

    private static AuditInsertionPoint bodyPoint(HttpRequestResponse base, String alteredBody) {
        return new AuditInsertionPoint() {
            @Override public String name() { return "body"; }
            @Override public String baseValue() { return ""; }
            @Override public AuditInsertionPointType type() { return AuditInsertionPointType.PARAM_JSON; }
            @Override public List<Range> issueHighlights(ByteArray payload) { return List.of(); }
            @Override public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
                return base.request().withBody(alteredBody);
            }
        };
    }

    private HttpRequestResponse baseWith(String body) {
        HttpRequest request = HttpRequest.httpRequestFromUrl("http://127.0.0.1:1/mcp")
                .withMethod("POST").withBody(body);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(exchange.request()).thenReturn(request);
        return exchange;
    }

    private AuditInsertionPoint nativePointAt(String... pathUnderArguments) {
        String[] keys = new String[pathUnderArguments.length + 1];
        keys[0] = "arguments";
        System.arraycopy(pathUnderArguments, 0, keys, 1, pathUnderArguments.length);
        return new BurpArgumentPoint(base.request(), keys);
    }

    private AuditInsertionPoint headerPoint() {
        return new AuditInsertionPoint() {
            @Override public String name() { return "header"; }
            @Override public String baseValue() { return ""; }
            @Override public AuditInsertionPointType type() { return AuditInsertionPointType.HEADER; }
            @Override public List<Range> issueHighlights(ByteArray payload) { return List.of(); }
            @Override public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
                return base.request().withHeader("X-Probe", payload.toString());
            }
        };
    }
}
