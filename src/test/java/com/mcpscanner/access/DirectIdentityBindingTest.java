package com.mcpscanner.access;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DirectIdentityBindingTest {

    private static final Principal PRIMARY = Principal.primary(() -> Map.of("Authorization", "Bearer alice"));
    private static final Principal BOB = new Principal("bob", "bob", PrincipalRole.PEER,
            () -> Map.of("Authorization", "Bearer bob"), Optional.empty(), Map.of());

    private final List<HttpRequest> sent = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();
    private final AtomicBoolean handleInBurpTools = new AtomicBoolean();
    private Function<HttpRequest, HttpResponse> server = request -> reply(200, Optional.of("bob-session"));
    private Optional<String> liveSession = Optional.of("live-session");
    private IdentityRequests requests;
    private HttpRequest primaryRequest;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest request = invocation.getArgument(0);
            sent.add(request);
            return HttpRequestResponse.httpRequestResponse(request, server.apply(request));
        });
        IdentityBinding direct = new DirectIdentityBinding(http, () -> liveSession, warnings::add);
        requests = new IdentityRequests(() -> PrincipalRoster.of(PRIMARY, List.of(BOB)),
                IdentityBinding.routedWhen(handleInBurpTools::get, direct));
        primaryRequest = ImmutableHttpRequest.post("http://mcp.test/mcp",
                Map.of("Authorization", "Bearer alice", McpHeaders.SESSION_ID, "live-session"), "{}");
    }

    @Test
    void offSendsAComparedUserWithItsOwnCredentialsAndASessionOpenedForIt() {
        HttpRequest bob = requests.as(BOB, primaryRequest);

        assertThat(bob.headerValue("Authorization")).isEqualTo("Bearer bob");
        assertThat(bob.headerValue(McpHeaders.SESSION_ID)).isEqualTo("bob-session");
        assertThat(scannerHeadersOf(bob)).isEmpty();
        assertThat(sent).extracting(request -> request.headerValue("Authorization")).containsOnly("Bearer bob");
        assertThat(sent).noneMatch(request -> "DELETE".equals(request.method()));
        assertThat(sent.get(0).hasHeader(McpHeaders.SESSION_ID)).isFalse();
        assertThat(sent.get(1).headerValue(McpHeaders.SESSION_ID)).isEqualTo("bob-session");
    }

    @Test
    void offSendsThePrimaryUserOnTheLiveSessionWithoutOpeningOne() {
        HttpRequest primary = requests.as(PRIMARY, primaryRequest.withRemovedHeader(McpHeaders.SESSION_ID));

        assertThat(primary.headerValue("Authorization")).isEqualTo("Bearer alice");
        assertThat(primary.headerValue(McpHeaders.SESSION_ID)).isEqualTo("live-session");
        assertThat(scannerHeadersOf(primary)).isEmpty();
        assertThat(sent).isEmpty();
    }

    @Test
    void offAgainstAStatelessServerSendsNoSessionHeader() {
        server = request -> reply(200, Optional.empty());
        liveSession = Optional.empty();

        assertThat(requests.as(BOB, primaryRequest).hasHeader(McpHeaders.SESSION_ID)).isFalse();
        assertThat(requests.as(PRIMARY, primaryRequest).hasHeader(McpHeaders.SESSION_ID)).isFalse();
        assertThat(sent).hasSize(1);
        assertThat(warnings).isEmpty();
    }

    @Test
    void offStillSendsWithoutASessionAndSaysWhyWhenTheServerRefusesOne() {
        server = request -> reply(401, Optional.empty());

        HttpRequest bob = requests.as(BOB, primaryRequest);

        assertThat(bob.hasHeader(McpHeaders.SESSION_ID)).isFalse();
        assertThat(bob.headerValue("Authorization")).isEqualTo("Bearer bob");
        assertThat(warnings).singleElement().asString().contains("bob").contains("401");
    }

    @Test
    void offStillSendsWithoutASessionAndSaysWhyWhenTheServerIsUnreachable() {
        server = request -> {
            throw new IllegalStateException("connection refused");
        };

        assertThat(requests.as(BOB, primaryRequest).hasHeader(McpHeaders.SESSION_ID)).isFalse();
        assertThat(warnings).singleElement().asString().contains("bob").contains("no reply");
    }

    @Test
    void onKeepsRoutingEveryPrincipalThroughTheProxy() {
        handleInBurpTools.set(true);

        HttpRequest bob = requests.as(BOB, primaryRequest);
        HttpRequest primary = requests.as(PRIMARY, primaryRequest);

        assertThat(bob.headerValue(ScannerSentinels.IDENTITY_HEADER)).isEqualTo("bob");
        assertThat(bob.hasHeader(McpHeaders.SESSION_ID)).isFalse();
        assertThat(primary.headerValue(ScannerSentinels.IDENTITY_HEADER)).isEqualTo(Principal.PRIMARY_ID);
        assertThat(sent).isEmpty();
    }

    private static List<String> scannerHeadersOf(HttpRequest request) {
        return request.headers().stream().map(header -> header.name())
                .filter(name -> name.toLowerCase().startsWith("x-mcp-scanner")).toList();
    }

    private static HttpResponse reply(int status, Optional<String> sessionId) {
        String session = sessionId.map(id -> McpHeaders.SESSION_ID + ": " + id + "\r\n").orElse("");
        return HttpResponse.httpResponse("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\n" + session
                + "\r\n{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{}}");
    }
}
