package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.catalog.oauthredirectpolicy.FakeAuthorizationServer.AuthorizationReply;
import com.mcpscanner.checks.catalog.oauthredirectpolicy.FakeAuthorizationServer.RegistrationReply;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class OAuthRedirectPolicyCheckTest {

    private static final String PREFIX = "Scan check: oauth-redirect-policy — ";
    private static final String MCP = "https://mcp.example.com/mcp";
    private static final String PRM = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
    private static final String AS_METADATA = "https://auth.example.com/.well-known/oauth-authorization-server";
    private static final String TOOLS_LIST = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
    private static final AuthStrategy COOKIE_STRATEGY = () -> Map.of("Cookie", "token=2");

    private final McpEventLog eventLog = mock(McpEventLog.class);
    private final OAuthRedirectPolicyCheck check = new OAuthRedirectPolicyCheck(eventLog, () -> COOKIE_STRATEGY);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    private static HttpRequestResponse base(String url, String method, String body) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(url).withMethod(method).withBody(body)
                .withAddedHeader("Cookie", "sid=1");
        return HttpRequestResponse.httpRequestResponse(request, null);
    }

    private static HttpRequestResponse mcpBase() {
        return base(MCP, "POST", TOOLS_LIST);
    }

    @Test
    void describesAHostCheckWithItsCatalogId() {
        assertThat(check.descriptor()).isSameAs(OAuthRedirectPolicyDescriptor.DESCRIPTOR);
        assertThat(check.descriptor().id()).isEqualTo("oauth-redirect-policy");
    }

    @Nested
    class AppliesTo {

        @Test
        void appliesToAnMcpJsonRpcRequest() {
            assertThat(check.appliesTo(mcpBase())).isTrue();
        }

        @Test
        void doesNotApplyToANonMcpPost() {
            assertThat(check.appliesTo(base(MCP, "POST", "{\"hello\":\"world\"}"))).isFalse();
        }

        @Test
        void doesNotApplyToAGet() {
            assertThat(check.appliesTo(base(MCP, "GET", TOOLS_LIST))).isFalse();
        }

        @Test
        void doesNotApplyToANonWebUrl() {
            assertThat(check.appliesTo(base("ftp://mcp.example.com/mcp", "POST", TOOLS_LIST))).isFalse();
        }

        @Test
        void doesNotApplyWithoutARequest() {
            assertThat(check.appliesTo(mock(HttpRequestResponse.class))).isFalse();
        }
    }

    @Nested
    class Audit {

        private FakeAuthorizationServer server;

        @BeforeEach
        void setUp() {
            server = new FakeAuthorizationServer();
            server.http().on("GET", PRM, RawResponses.json(
                    "{\"resource\":\"" + MCP + "\",\"authorization_servers\":[\"" + FakeAuthorizationServer.ISSUER
                            + "\"]}"));
        }

        private void publishMetadata(String authorizationEndpoint, boolean withRegistration) {
            server.http().on("GET", AS_METADATA, RawResponses.json("{\"issuer\":\"" + FakeAuthorizationServer.ISSUER
                    + "\",\"authorization_endpoint\":\"" + authorizationEndpoint + "\""
                    + (withRegistration ? ",\"registration_endpoint\":\""
                    + FakeAuthorizationServer.REGISTRATION_ENDPOINT + "\"" : "") + "}"));
        }

        private List<AuditIssue> audit() {
            return check.audit(mcpBase(), server.http().http());
        }

        @Test
        void skipsAndLogsWithoutARegistrationEndpoint() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), false);

            assertThat(audit()).isEmpty();
            assertThat(server.registrations()).isEmpty();
            verify(eventLog).info(PREFIX + "skipped " + MCP
                    + " (prerequisite missing: no authorization server with a registration endpoint discovered)");
        }

        @Test
        void stopsForATransportFailureWhenNothingAnswers() {
            assertThat(check.audit(mcpBase(), new ScriptedHttp().http())).isEmpty();
            verify(eventLog).info(PREFIX + "stopped " + MCP
                    + " (transport failure: no authorization server with a registration endpoint discovered)");
        }

        @Test
        void discoveryCutShortByHttp429IsLoggedAsRateLimited() {
            server.http().on("GET", AS_METADATA, RawResponses.status(429));

            audit();

            verify(eventLog).info(PREFIX + "stopped " + MCP + " (rate limited: the server answered HTTP 429)");
        }

        @Test
        void aRefusedLoopbackRegistrationSkipsTheLoopbackTests() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);
            server.registering(uris -> uris.get(0).startsWith("http://") ? RegistrationReply.REJECT
                    : RegistrationReply.ECHO);

            audit();

            verify(eventLog).info(PREFIX + "skipped the loopback-callback redirect tests for " + MCP
                    + " (prerequisite missing: dynamic client registration did not register a loopback callback)");
            verify(eventLog, never()).info(contains("https-callback"));
        }

        @Test
        void aRefusedHttpsRegistrationSkipsTheTestsThatNeedIt() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);
            server.registering(uris -> uris.get(0).startsWith("https://") ? RegistrationReply.REJECT
                    : RegistrationReply.ECHO);

            audit();

            verify(eventLog).info(PREFIX + "skipped the any-host registration, https-callback, script-scheme and wildcard "
                    + "redirect tests for "
                    + MCP + " (prerequisite missing: dynamic client registration did not register an https callback)");
            verify(eventLog, never()).info(contains("loopback-callback"));
        }

        @Test
        void reportsOnlyAnyHostRegistrationAgainstAServerThatMatchesRedirectsExactly() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);
            server.registering(uris -> uris.stream().allMatch(uri -> uri.startsWith("http"))
                    ? RegistrationReply.ECHO : RegistrationReply.REJECT);

            assertThat(audit()).extracting(AuditIssue::name)
                    .containsExactly(FindingKind.ANY_HOST_REGISTRATION.issueName());
            assertThat(server.authorizations()).isNotEmpty();
        }

        @Test
        void reportsNothingAgainstAServerThatRegistersOnlyLoopbackRedirects() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);
            server.registering(uris -> uris.stream().allMatch(uri -> uri.startsWith("http://127.0.0.1"))
                    ? RegistrationReply.ECHO : RegistrationReply.REJECT);

            assertThat(audit()).isEmpty();
            assertThat(server.authorizations()).isNotEmpty();
        }

        @Test
        void reportsDeliveryAndScriptSchemeIssuesAgainstALaxServer() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);
            server.redirecting(FakeAuthorizationServer.anyRedirect());

            assertThat(audit()).extracting(AuditIssue::name).containsExactly(
                    FindingKind.CODE_DELIVERY.issueName(),
                    FindingKind.ERROR_DELIVERY.issueName(),
                    FindingKind.SCRIPT_SCHEME_REGISTRATION.issueName(),
                    FindingKind.ANY_HOST_REGISTRATION.issueName());
        }

        @Test
        void reportsWildcardExpansionAgainstAWildcardMatchingServer() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);
            server.redirecting((redirectUri, registered) -> registered.contains(redirectUri)
                    || registered.stream().anyMatch(uri -> uri.contains("*")
                    && redirectUri.endsWith(uri.substring(uri.indexOf("*.") + 1)))
                    ? AuthorizationReply.DELIVER : AuthorizationReply.REJECT);

            assertThat(audit()).extracting(AuditIssue::name)
                    .contains(FindingKind.WILDCARD_EXPANSION.issueName())
                    .doesNotContain(FindingKind.CODE_DELIVERY.issueName());
        }

        @Test
        void sendsNoCookiesToACrossOriginAuthorizationEndpoint() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);

            audit();

            assertThat(server.authorizations()).isNotEmpty()
                    .allSatisfy(request -> assertThat(request.headerValue("Cookie")).isNull());
        }

        @Test
        void sendsMergedSessionCookiesToASameOriginAuthorizationEndpoint() {
            String sameOrigin = "https://mcp.example.com/authorize";
            publishMetadata(sameOrigin, true);
            server.http().on("GET", sameOrigin, RawResponses.status(400));

            audit();

            assertThat(server.http().sent("GET", sameOrigin)).isNotEmpty()
                    .allSatisfy(request -> assertThat(request.headerValue("Cookie")).isEqualTo("sid=1; token=2"));
        }
        @Test
        void deletesEveryProbeClientThroughRfc7592ClientManagement() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);
            server.managingClients().redirecting(FakeAuthorizationServer.anyRedirect());

            assertThat(audit()).isNotEmpty();
            int registered = server.registrations().size();
            assertThat(registered).isPositive();
            assertThat(server.deletions()).hasSize(registered)
                    .allSatisfy(request -> assertThat(request.headerValue("Authorization")).startsWith("Bearer rat-"));
            verify(eventLog).info(contains("deleted " + registered + " of " + registered));
        }

        @Test
        void leavesUnmanagedProbeClientsAndSaysSo() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);

            audit();

            assertThat(server.deletions()).isEmpty();
            verify(eventLog).info(contains("deleted 0 of " + server.registrations().size()));
        }

        @Test
        void stopsProbingWhenTheServerAnswersTooManyRequests() {
            publishMetadata(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT.toString(), true);
            server.throttlingAuthorization().redirecting(FakeAuthorizationServer.anyRedirect());

            assertThat(audit()).isEmpty();
            assertThat(server.authorizations()).hasSize(1);
            verify(eventLog).info(PREFIX + "stopped " + MCP + " (rate limited: the server answered HTTP 429)");
            verify(eventLog, never()).info(contains("skipped"));
        }
    }
}
