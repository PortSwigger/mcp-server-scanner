package com.mcpscanner.checks.api;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.SpentRateLimitQuota;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RateLimitedProbingTest {

    private static final String TOO_MANY_REQUESTS_LOG =
            "Scan check: demo — stopped field q (rate limited: the server answered HTTP 429)";
    private static final String QUOTA_SPENT_LOG =
            "Scan check: demo — stopped field q (rate limited: the server said no requests remain in its rate limit)";

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private final McpEventLog eventLog = new McpEventLog(null);
    private final RateLimitedProbing probing = new RateLimitedProbing(new CheckLog(eventLog, "demo"));
    private final AuditIssue issue = mock(AuditIssue.class);

    @Test
    void withholdsEveryProbeAfterTheFirstHttp429KeepsWhatWasFoundAndLogsWhy() {
        Http http = answering(reply(429));
        List<HttpRequestResponse> replies = new ArrayList<>();

        List<AuditIssue> issues = probing.run("field q", http, sends -> {
            for (int payload = 0; payload < 5; payload++) {
                replies.add(sends.probes().sendRequest(mock(HttpRequest.class)));
            }
            return List.of(issue);
        });

        assertThat(issues).containsExactly(issue);
        verify(http, times(1)).sendRequest(any(HttpRequest.class));
        assertThat(replies.subList(1, replies.size())).allSatisfy(reply -> assertThat(reply.response()).isNull());
        assertThat(messages()).containsExactly(TOO_MANY_REQUESTS_LOG);
    }

    @Test
    void anHttp429AlsoWithholdsConfirmations() {
        Http http = answering(reply(429));
        List<HttpRequestResponse> confirmations = new ArrayList<>();

        probing.run("field q", http, sends -> {
            sends.probes().sendRequest(mock(HttpRequest.class));
            confirmations.add(sends.confirmations().sendRequest(mock(HttpRequest.class)));
            return List.of();
        });

        verify(http, times(1)).sendRequest(any(HttpRequest.class));
        assertThat(confirmations).singleElement().satisfies(reply -> assertThat(reply.response()).isNull());
    }

    @Test
    void aSpentQuotaWithholdsFurtherProbesButLetsTheHitItCarriedBeConfirmed() {
        HttpRequestResponse hit = reply(200, SpentRateLimitQuota.mockedHeaders());
        HttpRequestResponse confirmed = reply(200);
        Http http = answering(hit, confirmed);
        List<HttpRequestResponse> replies = new ArrayList<>();

        probing.run("field q", http, sends -> {
            replies.add(sends.probes().sendRequest(mock(HttpRequest.class)));
            replies.add(sends.probes().sendRequest(mock(HttpRequest.class)));
            replies.add(sends.confirmations().sendRequest(mock(HttpRequest.class)));
            return List.of();
        });

        verify(http, times(2)).sendRequest(any(HttpRequest.class));
        assertThat(replies.get(0)).isSameAs(hit);
        assertThat(replies.get(1).response()).isNull();
        assertThat(replies.get(2)).isSameAs(confirmed);
        assertThat(messages()).containsExactly(QUOTA_SPENT_LOG);
    }

    @Test
    void anHttp429AfterASpentQuotaStillWithholdsConfirmationsAndIsTheReasonLogged() {
        Http http = answering(reply(401, SpentRateLimitQuota.mockedHeaders()), reply(429));
        List<HttpRequestResponse> replies = new ArrayList<>();

        probing.run("field q", http, sends -> {
            sends.probes().sendRequest(mock(HttpRequest.class));
            sends.confirmations().sendRequest(mock(HttpRequest.class));
            replies.add(sends.confirmations().sendRequest(mock(HttpRequest.class)));
            return List.of();
        });

        verify(http, times(2)).sendRequest(any(HttpRequest.class));
        assertThat(replies.get(0).response()).isNull();
        assertThat(messages()).containsExactly(TOO_MANY_REQUESTS_LOG);
    }

    @Test
    void passesOtherRepliesThroughUntouched() {
        Http http = answering(reply(200));

        List<AuditIssue> issues = probing.run("field q", http, sends -> {
            sends.probes().sendRequest(mock(HttpRequest.class));
            sends.confirmations().sendRequest(mock(HttpRequest.class));
            return List.of(issue);
        });

        assertThat(issues).containsExactly(issue);
        verify(http, times(2)).sendRequest(any(HttpRequest.class));
        assertThat(eventLog.snapshot()).isEmpty();
    }

    private List<String> messages() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }

    private static HttpRequestResponse reply(int status) {
        return reply(status, List.of());
    }

    private static HttpRequestResponse reply(int status, List<HttpHeader> headers) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) status);
        when(response.headers()).thenReturn(headers);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(exchange.response()).thenReturn(response);
        return exchange;
    }

    private static Http answering(HttpRequestResponse... exchanges) {
        Deque<HttpRequestResponse> scripted = new ArrayDeque<>(List.of(exchanges));
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation ->
                scripted.size() > 1 ? scripted.removeFirst() : scripted.peekFirst());
        return http;
    }
}
