package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BurpSessionPortsTest {

    private static final String ENDPOINT = "https://mcp.example.test/mcp";
    private static final String ANSWER = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";

    private final Http burp = mock(Http.class);
    private final List<HttpRequestResponse> recorded = new ArrayList<>();

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void anExchangeBurpReturnsWithTheDirectDeliverySentinelIsRecordedAsTheTargetReceivedIt() {
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenAnswer(sent ->
                HttpRequestResponse.httpRequestResponse(sent.getArgument(0), HttpResponse.httpResponse(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + ANSWER)));

        ports().post(new McpRequests.Request(ANSWER, Map.of("Authorization", "Bearer kept")));

        assertThat(recorded).singleElement().satisfies(exchange -> {
            assertThat(exchange.request().headers()).noneMatch(header -> ScannerSentinels.ALL.contains(header.name()));
            assertThat(exchange.request().headerValue("Authorization")).isEqualTo("Bearer kept");
            assertThat(exchange.response().bodyToString()).isEqualTo(ANSWER);
        });
    }

    @Test
    void anExchangeAlreadyFreeOfSentinelsIsRecordedAsBurpReturnedIt() {
        HttpRequestResponse returned = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl(ENDPOINT).withMethod("POST"),
                HttpResponse.httpResponse("HTTP/1.1 202 Accepted\r\n\r\n"));
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(returned);

        ports().post(new McpRequests.Request(ANSWER, Map.of()));

        assertThat(recorded).containsExactly(returned);
    }

    private BurpSessionPorts ports() {
        return new BurpSessionPorts(burp, ENDPOINT, recorded::add, RequestOptions.requestOptions(),
                new StreamingFallback(request -> Optional.empty(), request -> Optional.empty()));
    }
}
