package com.mcpscanner.auth.oauth;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link BurpHttpRequestSender}: verifies the Nimbus
 * {@code ReadOnlyHTTPRequest} ↔ Montoya {@code HttpRequest}/{@code HttpResponse}
 * mapping in both directions, the transport-failure ({@code response()==null})
 * contract, the non-2xx passthrough, and the read-timeout → {@code withResponseTimeout}
 * mapping.
 */
class BurpHttpRequestSenderTest {

    @BeforeEach
    void installFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void getRequestRoundTripsMethodUrlAndHeadersAndMapsResponseBack() throws Exception {
        Http http = mock(Http.class);
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        when(http.sendRequest(sent.capture(), any(RequestOptions.class)))
                .thenAnswer(inv -> responseOf(inv.getArgument(0), 200, "OK",
                        "{\"issuer\":\"https://as.example.com\"}",
                        "Content-Type", "application/json"));

        BurpHttpRequestSender sender = new BurpHttpRequestSender(http);

        HTTPRequest request = new HTTPRequest(HTTPRequest.Method.GET,
                new URL("https://as.example.com/.well-known/oauth-authorization-server"));
        request.setHeader("Accept", "application/json");
        request.setReadTimeout(10_000);

        HTTPResponse response = (HTTPResponse) sender.send(request);

        HttpRequest captured = sent.getValue();
        assertThat(captured.method()).isEqualTo("GET");
        assertThat(captured.url())
                .isEqualTo("https://as.example.com/.well-known/oauth-authorization-server");
        assertThat(captured.headerValue("Accept")).isEqualTo("application/json");

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("https://as.example.com");
        assertThat(response.getHeaderValue("Content-Type")).isEqualTo("application/json");
    }

    @Test
    void postRequestRoundTripsBodyAndContentTypeAndMultiValuedHeader() throws Exception {
        // A request mock that records every withAddedHeader call (the production
        // factory mock collapses duplicate names into a Map, hiding multi-values).
        HttpRequest recording = mock(HttpRequest.class);
        java.util.List<String[]> addedHeaders = new java.util.ArrayList<>();
        java.util.concurrent.atomic.AtomicReference<String> method =
                new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<String> body =
                new java.util.concurrent.atomic.AtomicReference<>();
        when(recording.withMethod(org.mockito.ArgumentMatchers.anyString()))
                .thenAnswer(inv -> { method.set(inv.getArgument(0)); return recording; });
        when(recording.withBody(org.mockito.ArgumentMatchers.anyString()))
                .thenAnswer(inv -> { body.set(inv.getArgument(0)); return recording; });
        when(recording.withAddedHeader(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString()))
                .thenAnswer(inv -> {
                    addedHeaders.add(new String[]{inv.getArgument(0), inv.getArgument(1)});
                    return recording;
                });

        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> HttpRequestResponse.httpRequestResponse(
                        inv.getArgument(0), multiValuedResponse()));

        BurpHttpRequestSender sender = new BurpHttpRequestSender(http, url -> recording);

        HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST,
                new URL("https://as.example.com/token"));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        // A multi-valued header (two values under the same name) must survive forward.
        request.setHeader("X-Multi", "one", "two");
        request.setBody("grant_type=refresh_token&refresh_token=abc");
        request.setReadTimeout(10_000);

        HTTPResponse response = (HTTPResponse) sender.send(request);

        assertThat(method.get()).isEqualTo("POST");
        assertThat(body.get()).isEqualTo("grant_type=refresh_token&refresh_token=abc");
        assertThat(addedHeaders)
                .anyMatch(h -> h[0].equals("Content-Type")
                        && h[1].equals("application/x-www-form-urlencoded"))
                .anyMatch(h -> h[0].equals("X-Multi") && h[1].equals("one"))
                .anyMatch(h -> h[0].equals("X-Multi") && h[1].equals("two"));

        // Multi-valued response header must survive back into the Nimbus response.
        assertThat(response.getHeaderMap().get("Set-Cookie")).containsExactly("a=1", "b=2");
    }

    @Test
    void nonSuccessStatusIsReturnedNotThrownWithBodyIntact() throws Exception {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> responseOf(inv.getArgument(0), 401, "Unauthorized",
                        "{\"error\":\"invalid_token\"}", "Content-Type", "application/json"));

        BurpHttpRequestSender sender = new BurpHttpRequestSender(http);

        HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST,
                new URL("https://as.example.com/register"));
        request.setReadTimeout(10_000);

        HTTPResponse response = (HTTPResponse) sender.send(request);

        assertThat(response.getStatusCode()).isEqualTo(401);
        assertThat(response.getBody()).contains("invalid_token");
    }

    @Test
    void nullResponseThrowsIOException() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> HttpRequestResponse.httpRequestResponse(inv.getArgument(0), null));

        BurpHttpRequestSender sender = new BurpHttpRequestSender(http);

        assertThatThrownBy(() -> {
            HTTPRequest request = new HTTPRequest(HTTPRequest.Method.GET,
                    new URL("https://as.example.com/.well-known/oauth-authorization-server"));
            request.setReadTimeout(10_000);
            sender.send(request);
        }).isInstanceOf(IOException.class);
    }

    @Test
    void readTimeoutMapsToWithResponseTimeout() throws Exception {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> responseOf(inv.getArgument(0), 200, "OK", "{}",
                        "Content-Type", "application/json"));

        BurpHttpRequestSender sender = new BurpHttpRequestSender(http);

        HTTPRequest request = new HTTPRequest(HTTPRequest.Method.GET,
                new URL("https://as.example.com/.well-known/oauth-authorization-server"));
        request.setReadTimeout(7_500);

        sender.send(request);

        ArgumentCaptor<RequestOptions> opts = ArgumentCaptor.forClass(RequestOptions.class);
        verify(http).sendRequest(any(HttpRequest.class), opts.capture());
        // The factory stub records withResponseTimeout(...) on its shared RequestOptions mock.
        verify(opts.getValue(), atLeastOnce()).withResponseTimeout(7_500L);
    }

    private static HttpRequestResponse responseOf(HttpRequest request, int status, String message,
                                                  String body, String... headerPairs) {
        StringBuilder raw = new StringBuilder("HTTP/1.1 ").append(status).append(' ')
                .append(message).append("\r\n");
        for (int i = 0; i + 1 < headerPairs.length; i += 2) {
            raw.append(headerPairs[i]).append(": ").append(headerPairs[i + 1]).append("\r\n");
        }
        raw.append("\r\n").append(body);
        return HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(raw.toString()));
    }

    private static HttpResponse multiValuedResponse() {
        String raw = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: application/json\r\n"
                + "Set-Cookie: a=1\r\n"
                + "Set-Cookie: b=2\r\n"
                + "\r\n"
                + "{}";
        return HttpResponse.httpResponse(raw);
    }
}
