package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.testutil.EvidenceTarget;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class EvidenceProducerFixtures {

    private EvidenceProducerFixtures() {
    }

    public static List<HttpRequestResponse> refusedByBurpAndSentOutside(HttpRequest probe) {
        Http burp = mock(Http.class);
        IllegalStateException refusal = new IllegalStateException("Streaming response received");
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(refusal);
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenThrow(refusal);
        return List.of(StreamingFallback.outsideBurp(EvidenceTarget.TIMEOUT).around(burp).sendRequest(probe));
    }
}
