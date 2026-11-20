package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizerTest {

    private static final URI AUTHORIZE = URI.create("https://auth.example.com/authorize");
    private static final URI CALLBACK = URI.create("https://client.example.com/cb");
    private static final Map<String, String> SESSION = Map.of("Cookie", "sid=1");

    private ScriptedHttp http;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        http = new ScriptedHttp();
    }

    private AuthorizationAttempt authorize() {
        return authorize(AuthorizationVariant.SILENT);
    }

    private AuthorizationAttempt authorize(AuthorizationVariant variant) {
        AuthorizationServer server = new AuthorizationServer(URI.create("https://auth.example.com"), AUTHORIZE,
                Optional.empty(), Optional.empty(), Optional.empty(), URI.create("https://mcp.example.com/mcp"), Optional.empty(),
                List.of());
        return new Authorizer(http.oauth(), new AuthorizationRequestFactory(server), SESSION)
                .authorize("client-1", CALLBACK, "state-1", variant);
    }

    @Test
    void sendsTheBuiltAuthorizationRequestAsABrowserWithTheSessionHeaders() {
        authorize();

        HttpRequest sent = http.sent().get(0);
        assertThat(sent.method()).isEqualTo("GET");
        assertThat(QueryParameters.of(sent.url()))
                .containsEntry("client_id", "client-1")
                .containsEntry("redirect_uri", CALLBACK.toString())
                .containsEntry("state", "state-1")
                .containsEntry("prompt", "none");
        assertThat(sent.headerValue("Accept")).isEqualTo("text/html,application/xhtml+xml");
        assertThat(sent.headerValue("Cookie")).isEqualTo("sid=1");
    }

    @Test
    void consentDenialPostsTheParametersAsAFormToTheAuthorizationEndpoint() {
        http.on("POST", AUTHORIZE.toString(), RawResponses.redirect("https://client.example.com/cb?error=access_denied"));

        AuthorizationAttempt attempt = authorize(AuthorizationVariant.CONSENT_DENIAL);

        HttpRequest sent = http.sent().get(0);
        assertThat(sent.method()).isEqualTo("POST");
        assertThat(sent.url()).isEqualTo(AUTHORIZE.toString());
        assertThat(sent.headerValue("Cookie")).isEqualTo("sid=1");
        assertThat(QueryParameters.ofEncoded(sent.bodyToString()))
                .containsEntry("redirect_uri", CALLBACK.toString())
                .containsEntry("state", "state-1")
                .containsEntry("allow", "false");
        assertThat(attempt.outcome().location()).isEqualTo("https://client.example.com/cb?error=access_denied");
    }

    @Test
    void recordsTheStatusLocationAndExchangeOfAResponse() {
        http.on("GET", AUTHORIZE.toString(), RawResponses.redirect("https://client.example.com/cb?code=c"));

        AuthorizationAttempt attempt = authorize();

        assertThat(attempt.outcome()).isEqualTo(new AuthorizationOutcome(302, "https://client.example.com/cb?code=c",
                true));
        assertThat(attempt.exchange()).isPresent();
    }

    @Test
    void recordsAResponseWithoutLocation() {
        http.on("GET", AUTHORIZE.toString(), RawResponses.status(200));

        assertThat(authorize().outcome()).isEqualTo(new AuthorizationOutcome(200, null, true));
    }

    @Test
    void isIncompleteWithoutAResponse() {
        AuthorizationAttempt attempt = authorize();

        assertThat(attempt.outcome()).isEqualTo(AuthorizationOutcome.incomplete());
        assertThat(attempt.outcome().complete()).isFalse();
        assertThat(attempt.exchange()).isEmpty();
    }
}
