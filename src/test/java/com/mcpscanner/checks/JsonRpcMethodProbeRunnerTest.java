package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JsonRpcMethodProbeRunnerTest {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private Http http;

    @Mock
    private HttpRequest baseline;

    @Mock
    private HttpRequest mutated;

    private JsonRpcMethodProbeRunner runner;

    @BeforeEach
    void setUp() {
        runner = new JsonRpcMethodProbeRunner(http);
        lenient().when(baseline.withBody(anyString())).thenReturn(mutated);
    }

    @Test
    void appliesProbeMethodToBodyAndPreservesParams() {
        HttpRequestResponse ok = httpRequestResponse(200, "{\"jsonrpc\":\"2.0\",\"result\":{}}", null);
        when(http.sendRequest(mutated)).thenReturn(ok);

        runner.runAll(baseline, List.of(new JsonRpcMethodProbe("admin.config")));

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(baseline).withBody(bodyCaptor.capture());
        String body = bodyCaptor.getValue();
        assertThat(body).contains("\"jsonrpc\":\"2.0\"");
        assertThat(body).contains("\"method\":\"admin.config\"");
        assertThat(body).contains("\"params\":{}");
        assertThat(body).contains("\"id\":");
    }

    @Test
    void successiveProbesUseDistinctRequestIds() {
        HttpRequestResponse ok = httpRequestResponse(200, "{\"jsonrpc\":\"2.0\",\"result\":{}}", null);
        when(http.sendRequest(mutated)).thenReturn(ok);

        runner.runAll(baseline,
                List.of(new JsonRpcMethodProbe("debug.info"), new JsonRpcMethodProbe("dev.info")));

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(baseline, times(2)).withBody(bodyCaptor.capture());
        List<String> bodies = bodyCaptor.getAllValues();
        assertThat(extractId(bodies.get(0))).isNotEqualTo(extractId(bodies.get(1)));
    }

    @Test
    void successResponseWithoutErrorIsSuspicious() {
        assertClassification("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}", null,
                JsonRpcMethodProbeRunner.Classification.SUSPICIOUS);
    }

    @Test
    void methodNotFoundErrorIsBoring() {
        assertClassification("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}",
                null, JsonRpcMethodProbeRunner.Classification.BORING);
    }

    @Test
    void invalidParamsErrorIsBoring() {
        // Real frameworks return -32602 for non-existent methods, so it is no longer a
        // "recognised method" signal.
        assertClassification("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}",
                null, JsonRpcMethodProbeRunner.Classification.BORING);
    }

    @Test
    void internalErrorIsBoring() {
        // -32603 is a generic exception returned for unknown methods too; no signal.
        assertClassification("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32603,\"message\":\"Internal\"}}",
                null, JsonRpcMethodProbeRunner.Classification.BORING);
    }

    @Test
    void serverDefinedErrorIsInteresting() {
        assertClassification("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32001,\"message\":\"Custom\"}}",
                null, JsonRpcMethodProbeRunner.Classification.INTERESTING);
    }

    @Test
    void sseFramedSuccessResponseIsSuspicious() {
        String sseBody = "event: message\n"
                + "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        assertClassification(sseBody, "text/event-stream; charset=utf-8",
                JsonRpcMethodProbeRunner.Classification.SUSPICIOUS);
    }

    @Test
    void sseFramedMethodNotFoundIsBoring() {
        String sseBody = "event: message\n"
                + "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}\n\n";
        assertClassification(sseBody, "text/event-stream",
                JsonRpcMethodProbeRunner.Classification.BORING);
    }

    @Test
    void mixedCaseSseContentTypeStillParsesAsEventStream() {
        String sseBody = "event: message\n"
                + "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32001,\"message\":\"server-defined\"}}\n\n";
        assertClassification(sseBody, "Text/Event-Stream",
                JsonRpcMethodProbeRunner.Classification.INTERESTING);
    }

    @Test
    void nonTwoHundredResponseIsHttpLayerError() {
        HttpRequestResponse rr = httpRequestResponse(500, "{\"error\":\"server\"}", null);
        when(http.sendRequest(mutated)).thenReturn(rr);

        List<JsonRpcMethodProbeRunner.ProbeResult> results = runner.runAll(baseline,
                List.of(new JsonRpcMethodProbe("test")));

        assertThat(results).singleElement()
                .satisfies(r -> assertThat(r.classification())
                        .isEqualTo(JsonRpcMethodProbeRunner.Classification.HTTP_LAYER_ERROR));
    }

    @Test
    void missingResponseIsHttpLayerError() {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        lenient().when(rr.response()).thenReturn(null);
        when(http.sendRequest(mutated)).thenReturn(rr);

        List<JsonRpcMethodProbeRunner.ProbeResult> results = runner.runAll(baseline,
                List.of(new JsonRpcMethodProbe("echo")));

        assertThat(results).singleElement()
                .satisfies(r -> assertThat(r.classification())
                        .isEqualTo(JsonRpcMethodProbeRunner.Classification.HTTP_LAYER_ERROR));
    }

    @Test
    void twoHundredButNeitherResultNorErrorIsNoSignal() {
        // The probe got a 200 OK back, but the body has neither a result envelope (so not
        // SUSPICIOUS) nor an error envelope (so not BORING/INTERESTING). The server is
        // reachable, but the response shape gives us no probe signal. Splitting this from
        // HTTP_LAYER_ERROR matters for dedup decisions in HiddenMethod.
        assertClassification("{\"jsonrpc\":\"2.0\",\"id\":1}", null,
                JsonRpcMethodProbeRunner.Classification.NO_SIGNAL);
    }

    @Test
    void twoHundredWithResultNullIsSuspicious() {
        // Hidden-method probes hit non-tool methods whose results can legitimately be
        // null (e.g. notifications-acknowledging methods, void-returning admin handlers).
        // The server returned a JSON-RPC result envelope at all — that means it recognised
        // the method. Must classify as SUSPICIOUS, not NO_SIGNAL.
        assertClassification("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}", null,
                JsonRpcMethodProbeRunner.Classification.SUSPICIOUS);
    }

    @Test
    void twoHundredWithIsErrorTrueIsSuspicious_methodRecognised() {
        // Hidden-method probe sees a tool-call-shaped error envelope back. From the
        // probe's perspective this still means the server recognised the method (it
        // dispatched and produced a tool-style failure rather than a -32601). Must
        // classify as SUSPICIOUS, not NO_SIGNAL.
        assertClassification(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"oops\"}]}}",
                null, JsonRpcMethodProbeRunner.Classification.SUSPICIOUS);
    }

    private void assertClassification(String body, String contentType,
                                      JsonRpcMethodProbeRunner.Classification expected) {
        HttpRequestResponse rr = httpRequestResponse(200, body, contentType);
        when(http.sendRequest(mutated)).thenReturn(rr);

        List<JsonRpcMethodProbeRunner.ProbeResult> results = runner.runAll(baseline,
                List.of(new JsonRpcMethodProbe("admin.config")));

        assertThat(results).singleElement()
                .satisfies(r -> assertThat(r.classification()).isEqualTo(expected));
    }

    private static long extractId(String body) {
        Matcher matcher = Pattern.compile("\"id\":(\\d+)").matcher(body);
        if (!matcher.find()) {
            throw new AssertionError("No id field in body: " + body);
        }
        return Long.parseLong(matcher.group(1));
    }

    private static HttpRequestResponse httpRequestResponse(int statusCode, String body, String contentType) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body);
        lenient().when(response.headerValue("Content-Type")).thenReturn(contentType);
        return rr;
    }
}
