package com.mcpscanner.mcp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitStopTest {

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void aTooManyRequestsAnswerStopsProbing() {
        assertThat(RateLimitStop.of(answered("HTTP/1.1 429 Too Many Requests\r\n\r\n")))
                .contains(RateLimitStop.TOO_MANY_REQUESTS);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "RateLimit-Remaining: 0\r\nRateLimit-Reset: 44",
            "ratelimit-remaining:  0 \r\nratelimit-reset: 10",
            "RateLimit: limit=60, remaining=0, reset=44",
            "RateLimit: \"default\";r=0;t=44",
            "RateLimit: \"burst\";r=5;t=1, \"daily\";r=0;t=3600",
            "RateLimit: \"burst\";r=5;t=1\r\nRateLimit: \"daily\";r=0;t=3600"})
    void anAnswerSayingNoRequestsRemainForAWhileStopsProbing(String quotaHeaders) {
        assertThat(RateLimitStop.of(answered("HTTP/1.1 401 Unauthorized\r\n" + quotaHeaders + "\r\n\r\n")))
                .contains(RateLimitStop.QUOTA_SPENT);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "RateLimit-Remaining: 1\r\nRateLimit-Reset: 44",
            "RateLimit-Remaining: 0",
            "RateLimit-Remaining: 0\r\nRateLimit-Reset: 9",
            "RateLimit: limit=60, remaining=0, reset=5",
            "RateLimit: limit=60, remaining=10, reset=44",
            "RateLimit: \"default\";r=10;t=44",
            "RateLimit: \"default\";r=0",
            "RateLimit: \"burst\";r=0;t=1, \"daily\";r=900;t=3600",
            "RateLimit: \"default\";r=0.5;t=44",
            "X-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 1795000000",
            "RateLimit-Remaining: 0\r\nRateLimit-Reset: 1795000000",
            "RateLimit-Policy: 60;w=60\r\nRateLimit-Reset: 44"})
    void anAnswerWithRequestsLeftOrASoonResetDoesNotStopProbing(String quotaHeaders) {
        assertThat(RateLimitStop.of(answered("HTTP/1.1 401 Unauthorized\r\n" + quotaHeaders + "\r\n\r\n"))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"HTTP/1.1 200 OK", "HTTP/1.1 202 Accepted", "HTTP/1.1 500 Internal Server Error"})
    void anyAnswerSayingNoRequestsRemainForAWhileStopsProbingWhateverItsStatus(String statusLine) {
        assertThat(RateLimitStop.of(answered(statusLine + "\r\nRateLimit-Remaining: 0\r\nRateLimit-Reset: 44\r\n\r\n")))
                .contains(RateLimitStop.QUOTA_SPENT);
    }

    @Test
    void anAnswerWithoutRateLimitHeadersDoesNotStopProbing() {
        assertThat(RateLimitStop.of(answered("HTTP/1.1 200 OK\r\n\r\n"))).isEmpty();
    }

    @Test
    void noAnswerDoesNotStopProbing() {
        assertThat(RateLimitStop.of(null)).isEmpty();
        assertThat(RateLimitStop.of(HttpRequestResponse.httpRequestResponse(request(), null))).isEmpty();
    }

    private static HttpRequestResponse answered(String response) {
        return HttpRequestResponse.httpRequestResponse(request(), HttpResponse.httpResponse(response));
    }

    private static HttpRequest request() {
        return ImmutableHttpRequest.post("http://mcp.example/mcp", Map.of(), "{}");
    }
}
