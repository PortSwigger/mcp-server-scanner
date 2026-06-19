package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizeProbeRunnerTest {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private Http http;

    @Test
    void buildsValidAuthorizeGetWithPkceAndState() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        HttpRequestResponse stubResponse = response(302, "https://x", "");
        when(http.sendRequest(captor.capture())).thenReturn(stubResponse);

        runner.send(new AuthorizeProbe(
                URI.create("https://auth.example.com/authorize"),
                "client-123",
                "https://probe.example/cb",
                "openid profile"));

        HttpRequest sent = captor.getValue();
        assertThat(sent.method()).isEqualTo("GET");
        String url = sent.url();
        assertThat(url).startsWith("https://auth.example.com/authorize?");
        assertThat(url).contains("response_type=code");
        assertThat(url).contains("client_id=client-123");
        assertThat(url).contains("redirect_uri=https%3A%2F%2Fprobe.example%2Fcb");
        assertThat(url).contains("code_challenge=");
        assertThat(url).contains("code_challenge_method=S256");
        assertThat(url).contains("state=");
        assertThat(url).contains("scope=openid+profile");
    }

    @Test
    void usesAmpersandWhenAuthorizeEndpointAlreadyHasQuery() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        HttpRequestResponse stubResponse = response(302, "https://x", "");
        when(http.sendRequest(captor.capture())).thenReturn(stubResponse);

        runner.send(new AuthorizeProbe(
                URI.create("https://auth.example.com/authorize?tenant=acme"),
                "client-123",
                "https://probe.example/cb",
                null));

        String url = captor.getValue().url();
        assertThat(url).startsWith("https://auth.example.com/authorize?tenant=acme&");
        assertThat(url).contains("&response_type=code");
        assertThat(url).doesNotContain("?response_type=code");
    }

    @Test
    void omitsScopeWhenNull() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        HttpRequestResponse stubResponse = response(302, "https://x", "");
        when(http.sendRequest(captor.capture())).thenReturn(stubResponse);

        runner.send(new AuthorizeProbe(
                URI.create("https://auth.example.com/authorize"),
                "client-123",
                "https://probe.example/cb",
                null));

        assertThat(captor.getValue().url()).doesNotContain("scope=");
    }

    @Test
    void freshPkceVerifierPerProbe() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        HttpRequestResponse stubResponse = response(302, "https://x", "");
        when(http.sendRequest(captor.capture())).thenReturn(stubResponse);

        AuthorizeProbe probe = new AuthorizeProbe(
                URI.create("https://auth.example.com/authorize"),
                "client-123", "https://probe.example/cb", null);
        runner.send(probe);
        runner.send(probe);

        String firstChallenge = challengeOf(captor.getAllValues().get(0).url());
        String secondChallenge = challengeOf(captor.getAllValues().get(1).url());
        assertThat(firstChallenge).isNotEqualTo(secondChallenge);
    }

    @Test
    void exposesStatusLocationAndBodyFromResponse() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        HttpRequestResponse stubResponse = response(302, "https://probe.example/cb?code=abc", "redirecting");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(stubResponse);

        AuthorizeProbeRunner.AuthorizeResult result = runner.send(new AuthorizeProbe(
                URI.create("https://auth.example.com/authorize"),
                "client-123", "https://probe.example/cb", null));

        assertThat(result.statusCode()).isEqualTo(302);
        assertThat(result.location()).isEqualTo("https://probe.example/cb?code=abc");
        assertThat(result.body()).isEqualTo("redirecting");
        assertThat(result.reachedServer()).isTrue();
    }

    @Test
    void marksNotReachedWhenResponseIsNull() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        lenient().when(rr.response()).thenReturn(null);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(rr);

        AuthorizeProbeRunner.AuthorizeResult result = runner.send(new AuthorizeProbe(
                URI.create("https://auth.example.com/authorize"),
                "client-123", "https://probe.example/cb", null));

        assertThat(result.reachedServer()).isFalse();
    }

    @Test
    void fetchSameOriginFollowsOneHopToSameOriginPath() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        HttpRequestResponse consentPage = response(200, null, "<html>consent</html>");
        when(http.sendRequest(captor.capture())).thenReturn(consentPage);

        AuthorizeProbeRunner.FetchResult result = runner.fetchSameOrigin(
                URI.create("https://auth.example.com/authorize"), "/authorize/consent");

        assertThat(result.fetched()).isTrue();
        assertThat(result.body()).isEqualTo("<html>consent</html>");
        assertThat(captor.getValue().url()).isEqualTo("https://auth.example.com/authorize/consent");
        assertThat(captor.getValue().method()).isEqualTo("GET");
    }

    @Test
    void fetchSameOriginResolvesRelativeLocationAgainstAuthorizeUrl() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        HttpRequestResponse consentPage = response(200, null, "ok");
        when(http.sendRequest(captor.capture())).thenReturn(consentPage);

        runner.fetchSameOrigin(URI.create("https://auth.example.com/oauth/authorize"), "consent?x=1");

        assertThat(captor.getValue().url()).isEqualTo("https://auth.example.com/oauth/consent?x=1");
    }

    @Test
    void fetchSameOriginRefusesCrossOriginLocation() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);

        AuthorizeProbeRunner.FetchResult result = runner.fetchSameOrigin(
                URI.create("https://auth.example.com/authorize"), "https://evil.example/consent");

        assertThat(result.fetched()).isFalse();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void fetchSameOriginRefusesAbsoluteSameHostDifferentScheme() {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);

        AuthorizeProbeRunner.FetchResult result = runner.fetchSameOrigin(
                URI.create("https://auth.example.com/authorize"), "http://auth.example.com/consent");

        assertThat(result.fetched()).isFalse();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    private static String challengeOf(String url) {
        for (String pair : url.substring(url.indexOf('?') + 1).split("&")) {
            if (pair.startsWith("code_challenge=")) {
                return pair.substring("code_challenge=".length());
            }
        }
        return "";
    }

    private HttpRequestResponse response(int status, String location, String body) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) status);
        lenient().when(response.headerValue("Location")).thenReturn(location);
        lenient().when(response.bodyToString()).thenReturn(body);
        return rr;
    }
}
