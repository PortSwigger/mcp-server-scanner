package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TargetPageTest {

    private static final String PAGE = "<html><title>Internal Admin Console</title></html>";

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void recognisesTheTargetPageTitleInAChunkFramedToolReply() {
        String reply = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\""
                + "<title>Internal Admin Console</title>\"}]}}";
        int split = reply.indexOf("Admin");
        String chunked = Integer.toHexString(split) + "\r\n" + reply.substring(0, split) + "\r\n"
                + Integer.toHexString(reply.length() - split) + "\r\n" + reply.substring(split) + "\r\n0\r\n\r\n";

        assertThat(page().shownIn(sent("application/json\r\nTransfer-Encoding: chunked", chunked))).isTrue();
    }

    private static TargetPage page() {
        HttpRequestResponse page = HttpRequestResponse.httpRequestResponse(base(),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + PAGE));
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(page);
        return TargetPage.fetch(http, base());
    }

    private static SentUrl sent(String contentType, String body) {
        return new SentUrl(ProbeUrl.loopback("127.0.0.1", 80), HttpRequestResponse.httpRequestResponse(base(),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\n\r\n" + body)));
    }

    private static HttpRequest base() {
        return HttpRequest.httpRequestFromUrl("https://api.example.com/mcp");
    }
}
