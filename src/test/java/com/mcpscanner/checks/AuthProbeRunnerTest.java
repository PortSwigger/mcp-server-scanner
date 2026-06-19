package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
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
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthProbeRunnerTest {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private Http http;

    @Mock
    private HttpRequest baseline;

    @Mock
    private HttpRequest afterRemoval;

    @Mock
    private HttpRequest afterOverride;

    private AuthProbeRunner runner;

    @BeforeEach
    void setUp() {
        runner = new AuthProbeRunner(http, this::successWhen200);
    }

    @Test
    void emptyProbeListReturnsEmptyResults() {
        List<AuthProbeRunner.ProbeResult> results = runner.runAll(baseline, List.of());

        assertThat(results).isEmpty();
        verifyNoInteractions(http);
    }

    @Test
    void successfulProbesAreReturnedInOrder() {
        AuthProbe probeA = new AuthProbe("A", Set.of(), Map.of("Authorization", "Bearer "));
        AuthProbe probeB = new AuthProbe("B", Set.of(), Map.of("Authorization", "Bearer junk"));
        HttpRequestResponse okA = httpRequestResponse(200);
        HttpRequestResponse okB = httpRequestResponse(200);
        when(baseline.withHeader("Authorization", "Bearer ")).thenReturn(afterOverride);
        when(baseline.withHeader("Authorization", "Bearer junk")).thenReturn(afterOverride);
        when(http.sendRequest(afterOverride)).thenReturn(okA, okB);

        List<AuthProbeRunner.ProbeResult> results = runner.runAll(baseline, List.of(probeA, probeB));

        assertThat(results).extracting(r -> r.probe().label()).containsExactly("A", "B");
    }

    @Test
    void probeWithFailedSuccessOracleIsExcluded() {
        AuthProbe probe = new AuthProbe("A", Set.of(), Map.of("Authorization", "Bearer "));
        HttpRequestResponse unauthorized = httpRequestResponse(401);
        when(baseline.withHeader("Authorization", "Bearer ")).thenReturn(afterOverride);
        when(http.sendRequest(afterOverride)).thenReturn(unauthorized);

        List<AuthProbeRunner.ProbeResult> results = runner.runAll(baseline, List.of(probe));

        assertThat(results).isEmpty();
    }

    @Test
    void headersToRemoveAreFilteredCaseInsensitively() {
        AuthProbe probe = new AuthProbe("strip", Set.of("Authorization", "Mcp-Session-Id"), Map.of());
        HttpHeader auth = httpHeader("authorization", "Bearer x");
        HttpHeader session = httpHeader("MCP-SESSION-ID", "abc");
        HttpHeader contentType = httpHeader("Content-Type", "application/json");
        HttpRequestResponse ok = httpRequestResponse(200);
        when(baseline.headers()).thenReturn(List.of(auth, session, contentType));
        when(baseline.withRemovedHeaders(anyList())).thenReturn(afterRemoval);
        when(http.sendRequest(afterRemoval)).thenReturn(ok);

        runner.runAll(baseline, List.of(probe));

        ArgumentCaptor<List<HttpHeader>> captor = captureRemovedHeaders();
        Set<String> removed = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        captor.getValue().forEach(h -> removed.add(h.name()));
        assertThat(removed).contains("authorization", "MCP-SESSION-ID");
        assertThat(removed).doesNotContain("Content-Type");
    }

    @Test
    void overridesAreAppliedAfterRemovals() {
        AuthProbe probe = new AuthProbe("strip-then-set",
                Set.of("Authorization"), Map.of("Authorization", "Bearer "));
        HttpHeader auth = httpHeader("Authorization", "Bearer original");
        HttpRequestResponse ok = httpRequestResponse(200);
        when(baseline.headers()).thenReturn(List.of(auth));
        when(baseline.withRemovedHeaders(anyList())).thenReturn(afterRemoval);
        when(afterRemoval.withHeader("Authorization", "Bearer ")).thenReturn(afterOverride);
        when(http.sendRequest(afterOverride)).thenReturn(ok);

        runner.runAll(baseline, List.of(probe));

        verify(http).sendRequest(eq(afterOverride));
    }

    @SuppressWarnings("unchecked")
    private ArgumentCaptor<List<HttpHeader>> captureRemovedHeaders() {
        ArgumentCaptor<List<HttpHeader>> captor = ArgumentCaptor.forClass(List.class);
        verify(baseline).withRemovedHeaders(captor.capture());
        return captor;
    }

    private boolean successWhen200(HttpRequestResponse response) {
        return response.response() != null && response.response().statusCode() == 200;
    }

    private HttpRequestResponse httpRequestResponse(int statusCode) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        return rr;
    }

    private HttpHeader httpHeader(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        lenient().when(header.name()).thenReturn(name);
        lenient().when(header.value()).thenReturn(value);
        return header;
    }
}
