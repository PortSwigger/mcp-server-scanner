package com.mcpscanner.client;

import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CopyOnWriteArrayList;

import static java.time.Duration.ofMillis;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RedirectLoggingInterceptorTest {

    @Test
    void logsWarnWhenHostDiffers() throws Exception {
        CapturedWarnings warnings = new CapturedWarnings();
        McpEventLog eventLog = warnings.attach(new McpEventLog(null));

        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.uri()).thenReturn(URI.create("https://different.example/path"));
        doReturn(response).when(client).send(any(), any());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://original.example/path"))
                .GET()
                .build();

        new RedirectLoggingInterceptor(eventLog)
                .sendAndLog(client, request, HttpResponse.BodyHandlers.ofString());

        String warning = warnings.awaitFirst();
        assertThat(warning).contains("Cross-origin redirect followed");
        assertThat(warning).contains("original.example");
        assertThat(warning).contains("different.example");
    }

    @Test
    void logsWarnWhenSchemeDiffers() throws Exception {
        CapturedWarnings warnings = new CapturedWarnings();
        McpEventLog eventLog = warnings.attach(new McpEventLog(null));

        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.uri()).thenReturn(URI.create("http://same.example/path"));
        doReturn(response).when(client).send(any(), any());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://same.example/path"))
                .GET()
                .build();

        new RedirectLoggingInterceptor(eventLog)
                .sendAndLog(client, request, HttpResponse.BodyHandlers.ofString());

        assertThat(warnings.awaitFirst()).contains("Cross-origin redirect followed");
    }

    @Test
    void logsWarnWhenPortDiffers() throws Exception {
        CapturedWarnings warnings = new CapturedWarnings();
        McpEventLog eventLog = warnings.attach(new McpEventLog(null));

        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.uri()).thenReturn(URI.create("https://same.example:9443/path"));
        doReturn(response).when(client).send(any(), any());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://same.example:8443/path"))
                .GET()
                .build();

        new RedirectLoggingInterceptor(eventLog)
                .sendAndLog(client, request, HttpResponse.BodyHandlers.ofString());

        assertThat(warnings.awaitFirst()).contains("Cross-origin redirect followed");
    }

    @Test
    void doesNotLogWhenSameOrigin() throws Exception {
        CapturedWarnings warnings = new CapturedWarnings();
        McpEventLog eventLog = warnings.attach(new McpEventLog(null));

        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.uri()).thenReturn(URI.create("https://same.example/path"));
        doReturn(response).when(client).send(any(), any());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://same.example/path"))
                .GET()
                .build();

        new RedirectLoggingInterceptor(eventLog)
                .sendAndLog(client, request, HttpResponse.BodyHandlers.ofString());

        warnings.assertNoneArriveWithin(150);
    }

    @Test
    void doesNotLogWhenExplicitDefaultPortMatches() throws Exception {
        CapturedWarnings warnings = new CapturedWarnings();
        McpEventLog eventLog = warnings.attach(new McpEventLog(null));

        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.uri()).thenReturn(URI.create("https://example.com:443/foo"));
        doReturn(response).when(client).send(any(), any());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://example.com/foo"))
                .GET()
                .build();

        new RedirectLoggingInterceptor(eventLog)
                .sendAndLog(client, request, HttpResponse.BodyHandlers.ofString());

        warnings.assertNoneArriveWithin(150);
    }

    @Test
    void doesNotLogWhenImplicitHttpPortMatchesExplicit() throws Exception {
        CapturedWarnings warnings = new CapturedWarnings();
        McpEventLog eventLog = warnings.attach(new McpEventLog(null));

        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.uri()).thenReturn(URI.create("http://example.com/foo"));
        doReturn(response).when(client).send(any(), any());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://example.com:80/foo"))
                .GET()
                .build();

        new RedirectLoggingInterceptor(eventLog)
                .sendAndLog(client, request, HttpResponse.BodyHandlers.ofString());

        warnings.assertNoneArriveWithin(150);
    }

    @Test
    void returnsResponseUnchanged() throws Exception {
        McpEventLog eventLog = new McpEventLog(null);

        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.uri()).thenReturn(URI.create("https://same.example/path"));
        doReturn(response).when(client).send(any(), any());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://same.example/path"))
                .GET()
                .build();

        HttpResponse<String> got = new RedirectLoggingInterceptor(eventLog)
                .sendAndLog(client, request, HttpResponse.BodyHandlers.ofString());

        assertThat(got).isSameAs(response);
    }

    private static final class CapturedWarnings {
        private final CopyOnWriteArrayList<String> warnings = new CopyOnWriteArrayList<>();

        McpEventLog attach(McpEventLog log) {
            log.subscribe(entry -> {
                if (entry.level() == McpEventLog.Level.WARN) {
                    warnings.add(entry.message());
                }
            });
            return log;
        }

        String awaitFirst() {
            await().atMost(ofSeconds(2)).until(() -> !warnings.isEmpty());
            return warnings.get(0);
        }

        void assertNoneArriveWithin(long millis) {
            await().during(ofMillis(millis)).atMost(ofMillis(millis + 500)).until(() -> warnings.isEmpty());
            assertThat(warnings).isEmpty();
        }
    }
}
