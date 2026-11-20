package com.mcpscanner.checks.catalog.oauthconsentstructurereflection;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.queryParameter;
import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationRequestTest {

    private static final AuthorizationServer SERVER = new AuthorizationServer(URI.create("https://as.example"),
            URI.create("https://as.example/authorize?tenant=t1"), Optional.of(URI.create("https://as.example/register")),
            Optional.empty(), Optional.empty(), URI.create("https://mcp.example/mcp"), Optional.of("read write"),
            List.of());

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void buildsAnS256CodeRequestPreservingTheEndpointQuery() {
        HttpRequest request = HttpRequest.httpRequestFromUrl(new AuthorizationRequest(
                SERVER, "client-1", URI.create("http://127.0.0.1:49151/callback"), "s\"<x> y").uri().toString());

        assertThat(queryParameter(request, "tenant")).isEqualTo("t1");
        assertThat(queryParameter(request, "response_type")).isEqualTo("code");
        assertThat(queryParameter(request, "client_id")).isEqualTo("client-1");
        assertThat(queryParameter(request, "redirect_uri")).isEqualTo("http://127.0.0.1:49151/callback");
        assertThat(queryParameter(request, "state")).isEqualTo("s\"<x> y");
        assertThat(queryParameter(request, "code_challenge_method")).isEqualTo("S256");
        assertThat(queryParameter(request, "code_challenge")).matches("[A-Za-z0-9_-]{43}");
        assertThat(queryParameter(request, "resource")).isEqualTo("https://mcp.example/mcp");
        assertThat(queryParameter(request, "scope")).isEqualTo("read write");
    }

    @Test
    void scopeIsOmittedWhenNoneWasDiscovered() {
        AuthorizationServer noScope = new AuthorizationServer(SERVER.issuer(), URI.create("https://as.example/authorize"),
                SERVER.registrationEndpoint(), SERVER.tokenEndpoint(), SERVER.revocationEndpoint(), SERVER.resource(), Optional.empty(),
                List.of());

        URI uri = new AuthorizationRequest(noScope, "c", URI.create("http://127.0.0.1/cb"), "s").uri();

        assertThat(uri.getRawQuery()).doesNotContain("scope=").startsWith("response_type=code");
    }

    @Test
    void forClientKeepsEverythingButTheClientId() {
        AuthorizationRequest request = new AuthorizationRequest(SERVER, "c", URI.create("http://127.0.0.1/cb"), "s");

        assertThat(request.forClient("other")).isEqualTo(
                new AuthorizationRequest(SERVER, "other", URI.create("http://127.0.0.1/cb"), "s"));
    }
}
