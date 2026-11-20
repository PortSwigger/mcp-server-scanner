package com.mcpscanner.checks.shared.oauth;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.http.ScanQueueBypass;
import com.mcpscanner.testutil.BurpEmptyResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.json;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.status;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class OAuthHttpTest {

    private static final String URL = "https://as.example/doc";
    private static final URI DOC = URI.create(URL);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void getSendsTheAcceptAndExtraHeadersAndReturnsTheExchange() {
        ScriptedHttp server = new ScriptedHttp().on("GET", URL, status(200));

        assertThat(server.oauth().get(DOC, "text/html", Map.of("Cookie", "sid=1"))).isPresent();

        HttpRequest sent = server.sent().get(0);
        assertThat(sent.method()).isEqualTo("GET");
        assertThat(sent.headerValue("Accept")).isEqualTo("text/html");
        assertThat(sent.headerValue("Cookie")).isEqualTo("sid=1");
    }

    @Test
    void getJsonAcceptsJson() {
        ScriptedHttp server = new ScriptedHttp();

        server.oauth().getJson(DOC);

        assertThat(server.sent().get(0).headerValue("Accept")).isEqualTo("application/json");
    }

    @Test
    void postFormSendsAnUrlEncodedBodyWithTheAcceptAndExtraHeaders() {
        ScriptedHttp server = new ScriptedHttp().on("POST", URL, status(201));

        assertThat(server.oauth().postForm(DOC, "a=1&b=2", "text/html", Map.of("Cookie", "sid=1")))
                .hasValueSatisfying(exchange -> assertThat(exchange.response().statusCode()).isEqualTo((short) 201));

        HttpRequest sent = server.sent().get(0);
        assertThat(sent.method()).isEqualTo("POST");
        assertThat(sent.headerValue("Content-Type")).isEqualTo("application/x-www-form-urlencoded");
        assertThat(sent.headerValue("Accept")).isEqualTo("text/html");
        assertThat(sent.headerValue("Cookie")).isEqualTo("sid=1");
        assertThat(sent.bodyToString()).isEqualTo("a=1&b=2");
    }

    @Test
    void postJsonSendsAJsonBody() {
        ScriptedHttp server = new ScriptedHttp().on("POST", URL, json(201, "{\"client_id\":\"c\"}"));

        assertThat(server.oauth().postJson(DOC, "{\"a\":1}")).isPresent();

        HttpRequest sent = server.sent().get(0);
        assertThat(sent.method()).isEqualTo("POST");
        assertThat(sent.headerValue("Content-Type")).isEqualTo("application/json");
        assertThat(sent.headerValue("Accept")).isEqualTo("application/json");
        assertThat(sent.bodyToString()).isEqualTo("{\"a\":1}");
    }

    @Test
    void deleteSendsTheExtraHeaders() {
        ScriptedHttp server = new ScriptedHttp().on("DELETE", URL, status(204));

        assertThat(server.oauth().delete(DOC, Map.of("Authorization", "Bearer t"))).isPresent();

        HttpRequest sent = server.sent().get(0);
        assertThat(sent.method()).isEqualTo("DELETE");
        assertThat(sent.headerValue("Authorization")).isEqualTo("Bearer t");
    }

    @Test
    void exchangeWithoutResponseIsEmpty() {
        ScriptedHttp server = new ScriptedHttp().on("GET", URL, ScriptedHttp.NO_RESPONSE);

        assertThat(server.oauth().get(DOC, "text/html")).isEmpty();
    }

    @Test
    void sendsOutsideTheScanQueueSoAnAuthorizationServersRateLimitPolicyCannotThrottleTheScan() {
        Http scanQueue = mock(Http.class);
        ScriptedHttp unqueued = new ScriptedHttp().on("GET", URL, status(200));

        assertThat(new OAuthHttp(ScanQueueBypass.through(unqueued.http()).around(scanQueue)).getJson(DOC))
                .isPresent();

        assertThat(unqueued.sent()).hasSize(1);
        verifyNoInteractions(scanQueue);
    }

    @Test
    void noExchangeIsEmpty() {
        assertThat(new OAuthHttp(mock(Http.class)).getJson(DOC)).isEmpty();
    }

    @Test
    void jsonDocumentRequiresASuccessfulObjectBody() {
        assertThat(new ScriptedHttp().on("GET", URL, json(200, "{\"k\":\"v\"}")).oauth().getJsonDocument(DOC))
                .hasValueSatisfying(document -> assertThat(document.text("k")).contains("v"));
        assertThat(new ScriptedHttp().on("GET", URL, json(404, "{\"k\":\"v\"}")).oauth().getJsonDocument(DOC))
                .isEmpty();
        assertThat(new ScriptedHttp().on("GET", URL, json(200, "[1]")).oauth().getJsonDocument(DOC)).isEmpty();
        assertThat(new ScriptedHttp().on("GET", URL, json(200, "<html>")).oauth().getJsonDocument(DOC)).isEmpty();
    }

    @Test
    void tooManyRequestsIsNoAnswerAndStopsEveryLaterRequest() {
        ScriptedHttp server = new ScriptedHttp().on("GET", URL, status(429)).on("POST", URL, status(201));
        OAuthHttp http = server.oauth();

        assertThat(http.rateLimited()).isFalse();
        assertThat(http.get(DOC, "text/html")).isEmpty();
        assertThat(http.rateLimited()).isTrue();
        assertThat(http.postJson(DOC, "{}")).isEmpty();
        assertThat(http.delete(DOC, Map.of())).isEmpty();
        assertThat(server.sent()).hasSize(1);
    }

    @Test
    void otherRefusalsDoNotStopProbing() {
        ScriptedHttp server = new ScriptedHttp().on("GET", URL, status(503));
        OAuthHttp http = server.oauth();

        assertThat(http.get(DOC, "text/html")).isPresent();
        assertThat(http.get(DOC, "text/html")).isPresent();
        assertThat(http.rateLimited()).isFalse();
    }

    @Test
    void sendGoesThroughTheSameRateLimit() {
        ScriptedHttp server = new ScriptedHttp().on("POST", URL, status(429));
        OAuthHttp http = server.oauth();

        assertThat(http.send(HttpRequest.httpRequestFromUrl(URL).withMethod("POST"))).isEmpty();
        assertThat(http.send(HttpRequest.httpRequestFromUrl(URL).withMethod("POST"))).isEmpty();
        assertThat(server.sent()).hasSize(1);
    }

    @Test
    void anAnsweredExchangeLeavesNoReasonForAMissingAnswer() {
        OAuthHttp http = new ScriptedHttp().on("GET", URL, status(404)).oauth();

        http.get(DOC, "text/html");

        assertThat(http.noAnswer()).isEmpty();
    }

    @Test
    void tooManyRequestsIsTheReasonForAMissingAnswer() {
        OAuthHttp http = new ScriptedHttp().on("GET", URL, status(429)).oauth();

        http.get(DOC, "text/html");

        assertThat(http.noAnswer()).contains(OAuthHttp.NoAnswer.RATE_LIMITED);
    }

    @Test
    void aStreamedReplyBurpWithheldIsTheReasonForAMissingAnswer() {
        Http streaming = mock(Http.class);
        when(streaming.sendRequest(any(HttpRequest.class)))
                .thenThrow(new IllegalStateException("Streaming response received"));
        OAuthHttp http = new OAuthHttp(streaming);

        assertThat(http.get(DOC, "text/html")).isEmpty();
        assertThat(http.noAnswer()).contains(OAuthHttp.NoAnswer.STREAMED_REPLY);
    }

    @Test
    void anExchangeWithoutResponseIsTheReasonForAMissingAnswer() {
        OAuthHttp http = new ScriptedHttp().on("GET", URL, ScriptedHttp.NO_RESPONSE).oauth();

        http.get(DOC, "text/html");

        assertThat(http.noAnswer()).contains(OAuthHttp.NoAnswer.NO_RESPONSE);
    }

    @Test
    void anEmptyReplyFromATimedOutOrIdleClosedSendIsNoAnswer() {
        Http idleClosed = mock(Http.class);
        when(idleClosed.sendRequest(any(HttpRequest.class))).thenAnswer(invocation ->
                HttpRequestResponse.httpRequestResponse(invocation.getArgument(0), BurpEmptyResponse.create()));
        OAuthHttp http = new OAuthHttp(idleClosed);

        assertThat(http.postJson(DOC, "{}")).isEmpty();
        assertThat(http.noAnswer()).contains(OAuthHttp.NoAnswer.NO_RESPONSE);
    }

    @Test
    void anEarlierMissingAnswerStillExplainsAfterLaterRefusals() {
        ScriptedHttp server = new ScriptedHttp().on("GET", URL, ScriptedHttp.NO_RESPONSE).on("POST", URL, status(400));
        OAuthHttp http = server.oauth();

        http.get(DOC, "text/html");
        http.postJson(DOC, "{}");

        assertThat(http.noAnswer()).contains(OAuthHttp.NoAnswer.NO_RESPONSE);
    }

    @Test
    void aMissingAnswerIsForgottenOnceALaterRequestSucceeds() {
        ScriptedHttp server = new ScriptedHttp().on("GET", URL, ScriptedHttp.NO_RESPONSE).on("POST", URL, status(200));
        OAuthHttp http = server.oauth();

        http.get(DOC, "text/html");
        http.postJson(DOC, "{}");

        assertThat(http.noAnswer()).isEmpty();
    }

    @Test
    void aRateLimitOutranksAnEarlierMissingAnswer() {
        ScriptedHttp server = new ScriptedHttp().on("GET", URL, ScriptedHttp.NO_RESPONSE).on("POST", URL, status(429));
        OAuthHttp http = server.oauth();

        http.get(DOC, "text/html");
        http.postJson(DOC, "{}");

        assertThat(http.noAnswer()).contains(OAuthHttp.NoAnswer.RATE_LIMITED);
    }
}
