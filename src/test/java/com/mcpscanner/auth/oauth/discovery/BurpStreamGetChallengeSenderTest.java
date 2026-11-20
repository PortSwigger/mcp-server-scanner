package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.BurpEmptyResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRequestOptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BurpStreamGetChallengeSenderTest {

    private static final URI SSE_ENDPOINT = URI.create("http://127.0.0.1:18800/sse");

    private final Http http = mock(Http.class);
    private final BurpStreamGetChallengeSender sender = new BurpStreamGetChallengeSender(http);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void sendsAnEventStreamGetThroughBurpWithoutFollowingRedirectsAndWithinTheProbeTimeout() {
        answerWith(unauthorized());

        sender.send(SSE_ENDPOINT);

        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        ArgumentCaptor<RequestOptions> options = ArgumentCaptor.forClass(RequestOptions.class);
        verify(http).sendRequest(request.capture(), options.capture());
        assertThat(request.getValue().method()).isEqualTo("GET");
        assertThat(request.getValue().headerValue("Accept")).isEqualTo("text/event-stream");
        RecordingRequestOptions sent = RecordingRequestOptions.recorded(options.getValue());
        assertThat(sent.redirectionMode()).contains(RedirectionMode.NEVER);
        assertThat(sent.responseTimeout()).contains(Duration.ofSeconds(5));
    }

    @Test
    void aChallengeIsReadFromBurpsReply() {
        answerWith(unauthorized());

        assertThat(sender.send(SSE_ENDPOINT))
                .contains(new ChallengeResponse(401, Optional.of("Bearer realm=\"mcp\"")));
    }

    @Test
    void aStreamBurpRefusesToHandOverIsAnAnonymousSuccess() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException("Streaming response received"));

        assertThat(sender.send(SSE_ENDPOINT)).contains(new ChallengeResponse(200, Optional.empty()));
    }

    @Test
    void noReplyFromBurpIsUnanswered() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(call -> HttpRequestResponse.httpRequestResponse(call.getArgument(0), null));

        assertThat(sender.send(SSE_ENDPOINT)).isEmpty();
    }

    @Test
    void theEmptyReplyBurpGivesWhenItsResponseTimeoutExpiresIsUnanswered() {
        answerWith(BurpEmptyResponse.create());

        assertThat(sender.send(SSE_ENDPOINT)).isEmpty();
    }

    private void answerWith(HttpResponse response) {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(call -> HttpRequestResponse.httpRequestResponse(call.getArgument(0), response));
    }

    private static HttpResponse unauthorized() {
        return HttpResponse.httpResponse("HTTP/1.1 401 Unauthorized\r\n"
                + "WWW-Authenticate: Bearer realm=\"mcp\"\r\n"
                + "Content-Length: 0\r\n\r\n");
    }
}
