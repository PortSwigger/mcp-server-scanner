package com.mcpscanner.checks.shared.oauth;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.json;
import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationServerDiscoveryTest {

    private static final String MCP = "https://mcp.example/tenant/mcp";
    private static final String PRM = "https://mcp.example/.well-known/oauth-protected-resource/tenant/mcp";
    private static final String ORIGIN_METADATA = "https://mcp.example/.well-known/oauth-authorization-server";
    private static final URI AUTHORIZE = URI.create("https://as.example/t1/authorize");
    private static final URI REGISTER = URI.create("https://as.example/t1/register");
    private static final URI TOKEN = URI.create("https://as.example/t1/token");
    private static final URI REVOKE = URI.create("https://as.example/t1/revoke");
    private static final String AS_METADATA = "{\"issuer\":\"https://as.example/t1\","
            + "\"authorization_endpoint\":\"" + AUTHORIZE + "\",\"registration_endpoint\":\"" + REGISTER + "\","
            + "\"token_endpoint\":\"" + TOKEN + "\",\"revocation_endpoint\":\"" + REVOKE + "\"}";

    private ScriptedHttp server;

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
        server = new ScriptedHttp();
    }

    @Test
    void combinesProtectedResourceAndAuthorizationServerMetadata() {
        server.on("GET", PRM, json(200, "{\"resource\":\"https://mcp.example/tenant/mcp\",\"authorization_servers\":"
                        + "[\"https://as.example/t1\"],\"scopes_supported\":[\"read\",\"write\"]}"))
                .on("GET", "https://as.example/.well-known/oauth-authorization-server/t1", json(200, AS_METADATA));

        assertThat(discover(base(null))).contains(new AuthorizationServer(URI.create("https://as.example/t1"),
                AUTHORIZE, Optional.of(REGISTER), Optional.of(TOKEN), Optional.of(REVOKE), URI.create(MCP),
                Optional.of("read write"), List.of()));
    }

    @Test
    void bearerChallengeOnTheBaseResponseNamesTheResourceMetadataAndScope() {
        server.on("GET", "https://mcp.example/custom-prm", json(200,
                        "{\"authorization_servers\":[\"https://as.example/t1\"],\"scopes_supported\":[\"x\"]}"))
                .on("GET", "https://as.example/t1/.well-known/openid-configuration", json(200, AS_METADATA));

        Optional<AuthorizationServer> discovered = discover(base(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer resource_metadata=\"https://mcp.example/"
                        + "custom-prm\", scope=\"mcp:tools\"\r\n\r\n"));

        assertThat(discovered).map(AuthorizationServer::scope).contains(Optional.of("mcp:tools"));
        assertThat(discovered).map(AuthorizationServer::resource).contains(URI.create(MCP));
        assertThat(server.sentTo("https://mcp.example/.well-known/oauth-protected-resource")).isEmpty();
    }

    @Test
    void withoutResourceMetadataTheMcpOriginAndEndpointAreUsed() {
        server.on("GET", ORIGIN_METADATA, json(200, "{\"authorization_endpoint\":\"" + AUTHORIZE + "\","
                + "\"registration_endpoint\":\"" + REGISTER + "\"}"));

        assertThat(discover(base(null))).contains(new AuthorizationServer(URI.create("https://mcp.example"),
                AUTHORIZE, Optional.of(REGISTER), Optional.empty(), Optional.empty(), URI.create(MCP), Optional.empty(), List.of()));
    }

    @Test
    void prefersTheIssuerDeclaredInTheMetadata() {
        server.on("GET", ORIGIN_METADATA, json(200, "{\"issuer\":\"https://issuer.example\","
                + "\"authorization_endpoint\":\"" + AUTHORIZE + "\"}"));

        assertThat(discover(base(null))).map(AuthorizationServer::issuer)
                .contains(URI.create("https://issuer.example"));
    }

    @Test
    void usesTheMcpEndpointAsResourceWhenTheDocumentOmitsIt() {
        server.on("GET", PRM, json(200, "{\"authorization_servers\":[\"https://as.example/t1\"]}"))
                .on("GET", "https://as.example/.well-known/oauth-authorization-server/t1", json(200, AS_METADATA));

        assertThat(discover(base(null))).hasValueSatisfying(found -> {
            assertThat(found.resource()).isEqualTo(URI.create(MCP));
            assertThat(found.issuer()).isEqualTo(URI.create("https://as.example/t1"));
        });
    }

    @Test
    void leavesTheRegistrationEndpointEmptyWhenTheMetadataOmitsIt() {
        server.on("GET", ORIGIN_METADATA, json(200, "{\"authorization_endpoint\":\"" + AUTHORIZE + "\"}"));

        assertThat(discover(base(null))).hasValueSatisfying(found ->
                assertThat(found.registrationEndpoint()).isEmpty());
    }

    @Test
    void nonHttpEndpointsAreRejected() {
        server.on("GET", ORIGIN_METADATA, json(200, "{\"authorization_endpoint\":\"javascript:alert(1)\","
                + "\"registration_endpoint\":\"" + REGISTER + "\"}"));

        assertThat(discover(base(null))).isEmpty();
    }

    @Test
    void nonHttpRegistrationEndpointIsDropped() {
        server.on("GET", ORIGIN_METADATA, json(200, "{\"authorization_endpoint\":\"" + AUTHORIZE + "\","
                + "\"registration_endpoint\":\"javascript:alert(1)\"}"));

        assertThat(discover(base(null))).hasValueSatisfying(found ->
                assertThat(found.registrationEndpoint()).isEmpty());
    }

    @Test
    void readsTheScopesTheAuthorizationServerSupports() {
        server.on("GET", ORIGIN_METADATA, json(200, "{\"authorization_endpoint\":\"" + AUTHORIZE + "\","
                + "\"scopes_supported\":[\"read\",\"write\",\"admin\"]}"));

        assertThat(discover(base(null))).map(AuthorizationServer::scopesSupported)
                .contains(List.of("read", "write", "admin"));
    }

    @Test
    void noMetadataAnywhereDiscoversNothing() {
        assertThat(discover(base(null))).isEmpty();
    }

    private Optional<AuthorizationServer> discover(HttpRequestResponse base) {
        return new AuthorizationServerDiscovery(server.oauth()).discover(base);
    }

    private static HttpRequestResponse base(String rawResponse) {
        return HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl(MCP).withMethod("POST")
                        .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"),
                rawResponse == null ? HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{}")
                        : HttpResponse.httpResponse(rawResponse));
    }
}
