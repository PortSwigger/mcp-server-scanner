package com.mcpscanner.checks.shared.probe;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.SpentRateLimitQuota;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ProbeChannelTest {

    private final Http http = mock(Http.class);

    private static HttpRequest probe() {
        return ImmutableHttpRequest.post("http://mcp.example/mcp", Map.of(), "{}");
    }

    @Test
    void sendsTheRequestUnchanged() {
        HttpRequest probe = probe();
        new ProbeChannel(http, 5).send(probe);

        verify(http).sendRequest(probe);
    }

    @Test
    void exchangesSentElsewhereCountAgainstTheBudgetAndARateLimitStopsIt() {
        MontoyaTestFactory.install();
        ProbeChannel channel = new ProbeChannel(http, 3);

        channel.record(HttpRequestResponse.httpRequestResponse(probe(), null));
        assertThat(channel.exhausted()).isFalse();
        channel.record(HttpRequestResponse.httpRequestResponse(probe(),
                HttpResponse.httpResponse("HTTP/1.1 429 Too Many Requests\r\n\r\n")));

        assertThat(channel.exhausted()).isTrue();
    }

    @Test
    void isExhaustedOnceTheBudgetIsSpent() {
        ProbeChannel channel = new ProbeChannel(http, 2);
        channel.send(probe());
        assertThat(channel.exhausted()).isFalse();

        channel.send(probe());

        assertThat(channel.exhausted()).isTrue();
    }

    @Test
    void isExhaustedOnceTheServerRateLimitsAProbe() {
        MontoyaTestFactory.install();
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> HttpRequestResponse.httpRequestResponse(
                invocation.getArgument(0), HttpResponse.httpResponse("HTTP/1.1 429 Too Many Requests\r\n\r\n")));
        ProbeChannel channel = new ProbeChannel(http, 10);

        channel.send(probe());

        assertThat(channel.exhausted()).isTrue();
    }

    @Test
    void isExhaustedOnceAnAnswerSaysNoRequestsRemainAndSaysWhy() {
        MontoyaTestFactory.install();
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> HttpRequestResponse.httpRequestResponse(
                invocation.getArgument(0),
                HttpResponse.httpResponse("HTTP/1.1 401 Unauthorized\r\n" + SpentRateLimitQuota.HEADER_LINES + "\r\n")));
        ProbeChannel channel = new ProbeChannel(http, 10);

        HttpRequestResponse answer = channel.send(probe());

        assertThat(answer.response().statusCode()).isEqualTo((short) 401);
        assertThat(channel.exhausted()).isTrue();
        assertThat(channel.exhaustion()).contains(ProbeChannel.Exhaustion.QUOTA_SPENT);
    }

    @Test
    void aSpentQuotaStopsNewProbesButStillLetsAHitBeConfirmed() {
        MontoyaTestFactory.install();
        ProbeChannel channel = new ProbeChannel(http, 10);

        channel.record(HttpRequestResponse.httpRequestResponse(probe(),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n" + SpentRateLimitQuota.HEADER_LINES + "\r\n")));

        assertThat(channel.exhausted()).isTrue();
        assertThat(channel.barsConfirmation()).isFalse();
    }

    @Test
    void aTooManyRequestsAnswerAfterASpentQuotaStillBarsConfirmation() {
        MontoyaTestFactory.install();
        ProbeChannel channel = new ProbeChannel(http, 10);
        channel.record(HttpRequestResponse.httpRequestResponse(probe(),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n" + SpentRateLimitQuota.HEADER_LINES + "\r\n")));
        channel.record(HttpRequestResponse.httpRequestResponse(probe(),
                HttpResponse.httpResponse("HTTP/1.1 429 Too Many Requests\r\n\r\n")));

        assertThat(channel.barsConfirmation()).isTrue();
        assertThat(channel.exhaustion()).contains(ProbeChannel.Exhaustion.RATE_LIMITED);
    }

    @Test
    void aTooManyRequestsAnswerOrASpentBudgetBarsConfirmation() {
        MontoyaTestFactory.install();
        ProbeChannel rateLimited = new ProbeChannel(http, 10);
        rateLimited.record(HttpRequestResponse.httpRequestResponse(probe(),
                HttpResponse.httpResponse("HTTP/1.1 429 Too Many Requests\r\n\r\n")));
        ProbeChannel spentBudget = new ProbeChannel(http, 1);
        spentBudget.send(probe());

        assertThat(rateLimited.barsConfirmation()).isTrue();
        assertThat(spentBudget.barsConfirmation()).isTrue();
        assertThat(new ProbeChannel(http, 10).barsConfirmation()).isFalse();
    }

    @Test
    void staysAvailableAfterAnAnswerThatIsNotARateLimit() {
        MontoyaTestFactory.install();
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> HttpRequestResponse.httpRequestResponse(
                invocation.getArgument(0), HttpResponse.httpResponse("HTTP/1.1 401 Unauthorized\r\n\r\n")));
        ProbeChannel channel = new ProbeChannel(http, 10);

        channel.send(probe());

        assertThat(channel.exhausted()).isFalse();
    }

    @Test
    void saysTheBudgetWasSpentOnceItIs() {
        ProbeChannel channel = new ProbeChannel(http, 1);
        assertThat(channel.exhaustion()).isEmpty();

        channel.send(probe());
        assertThat(channel.exhaustion()).isEmpty();

        assertThat(channel.exhausted()).isTrue();
        assertThat(channel.exhaustion()).contains(ProbeChannel.Exhaustion.BUDGET_SPENT);
        assertThat(channel.budget()).isEqualTo(1);
    }

    @Test
    void saysTheServerRateLimitedEvenWhenTheBudgetIsAlsoSpent() {
        MontoyaTestFactory.install();
        ProbeChannel channel = new ProbeChannel(http, 1);

        channel.record(HttpRequestResponse.httpRequestResponse(probe(),
                HttpResponse.httpResponse("HTTP/1.1 429 Too Many Requests\r\n\r\n")));

        assertThat(channel.exhaustion()).isEqualTo(Optional.of(ProbeChannel.Exhaustion.RATE_LIMITED));
    }
}
