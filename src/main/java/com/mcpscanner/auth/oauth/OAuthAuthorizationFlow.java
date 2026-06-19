package com.mcpscanner.auth.oauth;

import com.mcpscanner.ExtensionMetadata;
import com.mcpscanner.auth.oauth.safety.FetchPurpose;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;
import burp.api.montoya.http.Http;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientInformationResponse;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;


public class OAuthAuthorizationFlow {

    private static final String CALLBACK_PATH = "/callback";
    // IPv4 loopback literal, mirroring CallbackListener's bind host (its LOOPBACK_HOST is private).
    // RFC 8252 §8.3 recommends the IP literal so the advertised/opened redirect URI host matches the
    // bound listener — "localhost" can resolve to ::1 first (macOS/modern Linux), missing the bind.
    private static final String CALLBACK_HOST = "127.0.0.1";
    private static final String CLIENT_NAME = ExtensionMetadata.NAME;
    private static final int CONNECT_TIMEOUT_MILLIS = 5_000;
    private static final int READ_TIMEOUT_MILLIS = 10_000;

    private static final String PURPOSE_ISSUER_METADATA = "OAuth issuer metadata";
    private static final String PURPOSE_AUTHORIZATION_ENDPOINT = "OAuth authorization endpoint";
    private static final String PURPOSE_TOKEN_ENDPOINT = "OAuth token endpoint";
    private static final String PURPOSE_REGISTRATION_ENDPOINT = "OAuth registration endpoint";

    private final CallbackListenerFactory listenerFactory;
    private final BrowserLauncher browserLauncher;
    private final Clock clock;
    private final SuspiciousDestinationGate gate;
    private final McpEventLog eventLog;
    private final OAuthMetadataConsistencyListener anomalyListener;
    /**
     * Routes every Nimbus send (strict/lenient metadata resolve, DCR, token exchange, refresh)
     * through Burp's {@code api.http()}. Always non-null: construction without an {@link Http}
     * fails fast so there is a single Burp-routed networking path with no bypass.
     */
    private final BurpHttpRequestSender burpSender;

    /**
     * Canonical constructor. Routes all Nimbus token/DCR/metadata HTTP through Burp's
     * {@code api.http()} via the supplied {@link Http}, which is required.
     */
    public OAuthAuthorizationFlow(CallbackListenerFactory listenerFactory,
                                   BrowserLauncher browserLauncher,
                                   Clock clock,
                                   SuspiciousDestinationGate gate,
                                   McpEventLog eventLog,
                                   OAuthMetadataConsistencyListener anomalyListener,
                                   Http http) {
        this.listenerFactory = listenerFactory;
        this.browserLauncher = browserLauncher;
        this.clock = clock;
        this.gate = gate;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
        this.anomalyListener = anomalyListener != null ? anomalyListener : OAuthMetadataConsistencyListener.noop();
        this.burpSender = new BurpHttpRequestSender(Objects.requireNonNull(http, "http must not be null"));
    }

    public OAuthSession connect(URI mcpResource, OAuthClientHints hints) {
        info("OAuth flow starting - issuer=" + hints.issuer()
                + ", dcr=" + (hints.allowDcr() && hints.clientId() == null ? "yes" : "no"));
        try (CallbackListener listener = listenerFactory.start(hints.redirectPort(), CALLBACK_PATH)) {
            int boundPort = listener.port();
            AuthorizationServerMetadata metadata = resolveMetadata(hints.issuer(), mcpResource);
            ClientCredentials credentials = resolveCredentials(metadata, hints, boundPort);
            OAuthTokens tokens = runAuthorizationDance(mcpResource, hints, metadata, credentials,
                    listener, boundPort);
            return new OAuthSession(tokens, credentials.clientId(), credentials.clientSecret(),
                    credentials.registrationAccessToken(), credentials.registrationClientUri());
        } catch (IOException e) {
            throw new OAuthException("Failed to start callback listener on port " + hints.redirectPort()
                    + ": " + e.getMessage(), e);
        }
    }

    public OAuthTokens refresh(URI issuer, String clientId, String clientSecret, RefreshToken refreshToken,
                                URI mcpResource) {
        AuthorizationServerMetadata metadata = resolveMetadata(issuer, mcpResource);
        TokenRequest request = buildRefreshTokenRequest(metadata, clientId, clientSecret, refreshToken, mcpResource);
        TokenResponse response = sendTokenRequest(request);
        return toOAuthTokens(response);
    }

    private AuthorizationServerMetadata resolveMetadata(URI issuer, URI mcpResource) {
        if (issuer == null) {
            throw new OAuthException("OAuth issuer URI is required");
        }
        gateOrThrow(issuer, PURPOSE_ISSUER_METADATA, mcpResource, null);
        return resolveMetadataStrict(new Issuer(issuer.toString()), mcpResource);
    }

    /**
     * Strict RFC 8414 resolve routed through Burp's {@code api.http()}. Mirrors Nimbus's
     * own {@code AuthorizationServerMetadata.resolve(...)}: fetch the config URL, parse it,
     * and require the declared {@code issuer} to equal the expected issuer. On a mismatch we
     * fall back to {@link #resolveMetadataLenient} (which re-fetches via the sender, emits
     * the §3.3 warning and {@code notifyIssuerMismatch}); on a transport failure we surface
     * an {@link OAuthException}.
     */
    private AuthorizationServerMetadata resolveMetadataStrict(Issuer nimbusIssuer, URI mcpResource) {
        try {
            java.net.URL configURL = AuthorizationServerMetadata.resolveURL(nimbusIssuer);
            HTTPRequest req = new HTTPRequest(HTTPRequest.Method.GET, configURL);
            req.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
            req.setReadTimeout(READ_TIMEOUT_MILLIS);
            HTTPResponse resp = req.send(burpSender);
            resp.ensureStatusCode(200);
            AuthorizationServerMetadata metadata =
                    AuthorizationServerMetadata.parse(JSONObjectUtils.parse(resp.getBody()));
            if (!nimbusIssuer.equals(metadata.getIssuer())) {
                return resolveMetadataLenient(nimbusIssuer, mcpResource);
            }
            validateMetadataEndpoints(metadata, mcpResource, toUri(configURL), new byte[0]);
            return metadata;
        } catch (GeneralException | IOException e) {
            throw new OAuthException("Failed to resolve authorization server metadata: " + e.getMessage(), e);
        }
    }

    private AuthorizationServerMetadata resolveMetadataLenient(Issuer nimbusIssuer, URI mcpResource) {
        try {
            java.net.URL configURL = AuthorizationServerMetadata.resolveURL(nimbusIssuer);
            URI configUri = toUri(configURL);
            if (configUri != null) {
                gateOrThrow(configUri, PURPOSE_ISSUER_METADATA, mcpResource, URI.create(nimbusIssuer.getValue()));
            }
            HTTPRequest req = new HTTPRequest(HTTPRequest.Method.GET, configURL);
            req.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
            req.setReadTimeout(READ_TIMEOUT_MILLIS);
            HTTPResponse resp = req.send(burpSender);
            resp.ensureStatusCode(200);
            String rawBody = resp.getBody();
            AuthorizationServerMetadata metadata =
                    AuthorizationServerMetadata.parse(JSONObjectUtils.parse(rawBody));
            String returned = metadata.getIssuer() != null ? metadata.getIssuer().getValue() : "<missing>";
            warn("AS metadata RFC 8414 §3.3 violation: fetched " + configURL
                    + ", expected issuer " + nimbusIssuer.getValue()
                    + ", server declared " + returned
                    + ". Proceeding in lenient mode.");
            notifyIssuerMismatch(configURL, nimbusIssuer.getValue(), returned, rawBody);
            byte[] rawBodyBytes = (rawBody != null ? rawBody : "").getBytes(StandardCharsets.UTF_8);
            validateMetadataEndpoints(metadata, mcpResource, configUri, rawBodyBytes);
            return metadata;
        } catch (GeneralException | IOException e) {
            throw new OAuthException("Failed to resolve authorization server metadata: " + e.getMessage(), e);
        }
    }

    private void notifyIssuerMismatch(java.net.URL configUrl,
                                      String expectedIssuer,
                                      String returnedIssuer,
                                      String rawBody) {
        URI metadataUrl = toUri(configUrl);
        if (metadataUrl == null) {
            return;
        }
        byte[] bodyBytes = (rawBody != null ? rawBody : "").getBytes(StandardCharsets.UTF_8);
        try {
            anomalyListener.onIssuerMismatch(metadataUrl, expectedIssuer, returnedIssuer, bodyBytes);
        } catch (RuntimeException listenerFailure) {
            warn("OAuthMetadataConsistencyListener.onIssuerMismatch threw "
                    + listenerFailure.getClass().getSimpleName()
                    + ": " + listenerFailure.getMessage()
                    + " (continuing with lenient metadata)");
        }
    }

    private static URI toUri(java.net.URL configUrl) {
        if (configUrl == null) {
            return null;
        }
        try {
            return configUrl.toURI();
        } catch (URISyntaxException ignored) {
            return null;
        }
    }

    private void validateMetadataEndpoints(AuthorizationServerMetadata metadata,
                                            URI mcpResource,
                                            URI metadataUri,
                                            byte[] rawAsBody) {
        gateMetadataEndpoint(metadata.getAuthorizationEndpointURI(), PURPOSE_AUTHORIZATION_ENDPOINT, mcpResource);
        gateMetadataEndpoint(metadata.getTokenEndpointURI(), PURPOSE_TOKEN_ENDPOINT, mcpResource);
        gateMetadataEndpoint(metadata.getRegistrationEndpointURI(), PURPOSE_REGISTRATION_ENDPOINT, mcpResource);
        checkAsEndpointHosts(metadata, metadataUri, rawAsBody);
    }

    private void gateMetadataEndpoint(URI endpoint, String purpose, URI mcpResource) {
        if (endpoint == null) {
            return;
        }
        gateOrThrow(endpoint, purpose, mcpResource, null);
    }

    private void checkAsEndpointHosts(AuthorizationServerMetadata metadata,
                                       URI metadataUri,
                                       byte[] rawAsBody) {
        if (metadata.getIssuer() == null || metadataUri == null) {
            return;
        }
        String issuerValue = metadata.getIssuer().getValue();
        String issuerHost = hostOf(URI.create(issuerValue));
        if (issuerHost == null) {
            return;
        }
        checkEndpointHost(metadata.getAuthorizationEndpointURI(), "authorization_endpoint",
                issuerValue, issuerHost, metadataUri, rawAsBody);
        checkEndpointHost(metadata.getTokenEndpointURI(), "token_endpoint",
                issuerValue, issuerHost, metadataUri, rawAsBody);
        checkEndpointHost(metadata.getRegistrationEndpointURI(), "registration_endpoint",
                issuerValue, issuerHost, metadataUri, rawAsBody);
    }

    private void checkEndpointHost(URI endpoint,
                                    String endpointName,
                                    String issuerValue,
                                    String issuerHost,
                                    URI metadataUri,
                                    byte[] rawAsBody) {
        if (endpoint == null) {
            return;
        }
        String endpointHost = hostOf(endpoint);
        if (endpointHost == null || endpointHost.equalsIgnoreCase(issuerHost)) {
            return;
        }
        warn("AS metadata endpoint host mismatch: " + endpointName + " is on " + endpointHost
                + " but issuer is " + issuerHost + ". Proceeding permissively.");
        try {
            anomalyListener.onAsEndpointHostMismatch(metadataUri, issuerValue,
                    endpointName, endpoint.toString(), rawAsBody);
        } catch (RuntimeException listenerFailure) {
            warn("OAuthMetadataConsistencyListener.onAsEndpointHostMismatch threw "
                    + listenerFailure.getClass().getSimpleName()
                    + ": " + listenerFailure.getMessage()
                    + " (continuing with metadata)");
        }
    }

    private static String hostOf(URI uri) {
        if (uri == null) {
            return null;
        }
        try {
            return uri.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private void gateOrThrow(URI url, String purposeLabel, URI mcpResource, URI sourceUrl) {
        FetchPurpose purpose = FetchPurpose.of(purposeLabel, mcpResource, sourceUrl);
        SuspiciousDestinationGate.Decision decision = gate.evaluate(url, purpose);
        if (decision.isDenied()) {
            String detail = decision.reason() != null
                    ? decision.reason().userMessage()
                    : "destination rejected";
            throw new OAuthException("Refusing to fetch " + purposeLabel + ": " + detail);
        }
    }

    private ClientCredentials resolveCredentials(AuthorizationServerMetadata metadata,
                                                  OAuthClientHints hints,
                                                  int boundPort) {
        if (hints.clientId() != null) {
            info("DCR skipped - client_id already provided");
            return new ClientCredentials(hints.clientId(), hints.clientSecret());
        }
        if (!hints.allowDcr()) {
            throw new OAuthException("No client_id provided and DCR is disabled");
        }
        return registerClient(metadata, hints, boundPort);
    }

    private ClientCredentials registerClient(AuthorizationServerMetadata metadata,
                                              OAuthClientHints hints,
                                              int boundPort) {
        URI registrationEndpoint = metadata.getRegistrationEndpointURI();
        if (registrationEndpoint == null) {
            warn("DCR registration failed: authorization server does not advertise a registration endpoint");
            throw new DcrUnsupportedException("Authorization server does not advertise a registration endpoint");
        }
        try {
            ClientMetadata clientMetadata = buildClientMetadata(hints, boundPort);
            ClientRegistrationRequest registrationRequest =
                    new ClientRegistrationRequest(registrationEndpoint, clientMetadata, null);
            HTTPResponse httpResponse = sendWithTimeouts(registrationRequest.toHTTPRequest());
            ClientRegistrationResponse response = ClientRegistrationResponse.parse(httpResponse);
            if (!response.indicatesSuccess()) {
                ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse) response;
                String detail = describeRegistrationError(errorResponse.getErrorObject(), httpResponse);
                warn("DCR registration failed: " + detail);
                throw new DcrUnsupportedException("Dynamic client registration failed: " + detail);
            }
            ClientInformationResponse success = (ClientInformationResponse) response;
            com.nimbusds.oauth2.sdk.client.ClientInformation clientInfo = success.getClientInformation();
            String registeredId = clientInfo.getID().getValue();
            Secret registeredSecret = clientInfo.getSecret();
            com.nimbusds.oauth2.sdk.token.BearerAccessToken regToken = clientInfo.getRegistrationAccessToken();
            java.net.URI regUri = clientInfo.getRegistrationURI();
            info("DCR registered new client_id=" + registeredId);
            return new ClientCredentials(
                    registeredId,
                    registeredSecret != null ? registeredSecret.getValue() : null,
                    regToken != null ? Optional.of(regToken.getValue()) : Optional.empty(),
                    regUri != null ? Optional.of(regUri.toString()) : Optional.empty());
        } catch (IOException | com.nimbusds.oauth2.sdk.ParseException e) {
            String detail = messageOf(e);
            warn("DCR registration failed: " + detail);
            throw new OAuthException("Dynamic client registration error: " + detail, e);
        }
    }

    private static final int DCR_ERROR_BODY_EXCERPT_LIMIT = 200;

    private String describeRegistrationError(ErrorObject errorObject, HTTPResponse httpResponse) {
        StringBuilder detail = new StringBuilder("HTTP ").append(httpResponse.getStatusCode());
        String code = errorObject != null ? errorObject.getCode() : null;
        if (code != null && !code.isEmpty()) {
            detail.append(' ').append(code);
        }
        String description = errorObject != null ? errorObject.getDescription() : null;
        if (description != null && !description.isEmpty()) {
            detail.append(" — ").append(description);
        }
        detail.append(' ').append(formatBodyExcerpt(httpResponse.getBody()));
        return detail.toString();
    }

    private String formatBodyExcerpt(String body) {
        if (body == null || body.isBlank()) {
            return "(empty response body)";
        }
        String trimmed = body.trim();
        if (trimmed.length() > DCR_ERROR_BODY_EXCERPT_LIMIT) {
            trimmed = trimmed.substring(0, DCR_ERROR_BODY_EXCERPT_LIMIT) + "…";
        }
        return "(body: " + trimmed + ")";
    }

    private String messageOf(Throwable e) {
        String message = e.getMessage();
        return (message != null && !message.isEmpty()) ? message : e.getClass().getSimpleName();
    }

    private ClientMetadata buildClientMetadata(OAuthClientHints hints, int boundPort) {
        ClientMetadata metadata = new ClientMetadata();
        metadata.setRedirectionURIs(Set.of(URI.create("http://" + CALLBACK_HOST + ":" + boundPort + CALLBACK_PATH)));
        metadata.setGrantTypes(Set.of(
                com.nimbusds.oauth2.sdk.GrantType.AUTHORIZATION_CODE,
                com.nimbusds.oauth2.sdk.GrantType.REFRESH_TOKEN));
        metadata.setResponseTypes(Set.of(ResponseType.CODE));
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.NONE);
        metadata.setName(CLIENT_NAME);
        if (!hints.scopes().isEmpty()) {
            metadata.setScope(new Scope(hints.scopes().toArray(String[]::new)));
        }
        return metadata;
    }

    private OAuthTokens runAuthorizationDance(URI mcpResource,
                                               OAuthClientHints hints,
                                               AuthorizationServerMetadata metadata,
                                               ClientCredentials credentials,
                                               CallbackListener listener,
                                               int boundPort) {
        CodeVerifier verifier = new CodeVerifier();
        State state = new State();
        URI redirectForFlow = URI.create("http://" + CALLBACK_HOST + ":" + boundPort + CALLBACK_PATH);
        AuthorizationRequest request = buildAuthorizationRequest(
                mcpResource, hints, metadata, credentials, verifier, state, redirectForFlow);

        info("Opening browser to authorization endpoint");
        browserLauncher.open(request.toURI());

        CallbackResult result = waitForCallback(listener, hints.timeout());
        verifyCallback(result, state);

        return exchangeCodeForTokens(mcpResource, hints, metadata, credentials,
                new AuthorizationCode(result.code()), verifier, redirectForFlow);
    }

    private AuthorizationRequest buildAuthorizationRequest(URI mcpResource,
                                                            OAuthClientHints hints,
                                                            AuthorizationServerMetadata metadata,
                                                            ClientCredentials credentials,
                                                            CodeVerifier verifier,
                                                            State state,
                                                            URI redirectUri) {
        AuthorizationRequest.Builder builder = new AuthorizationRequest.Builder(
                ResponseType.CODE, new ClientID(credentials.clientId()))
                .endpointURI(metadata.getAuthorizationEndpointURI())
                .redirectionURI(redirectUri)
                .state(state)
                .codeChallenge(verifier, CodeChallengeMethod.S256);
        Scope resolvedScope = resolveScopes(hints);
        if (resolvedScope != null) {
            builder.scope(resolvedScope);
        }
        if (mcpResource != null) {
            builder.resource(mcpResource);
        }
        return builder.build();
    }

    private Scope resolveScopes(OAuthClientHints hints) {
        if (hints.scopes().isEmpty()) {
            return null;
        }
        return new Scope(hints.scopes().toArray(String[]::new));
    }

    private CallbackResult waitForCallback(CallbackListener listener, Duration timeout) {
        try {
            return listener.awaitCallback().get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            throw new OAuthException("Timed out waiting for OAuth callback after " + timeout.toSeconds() + "s", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OAuthException("Interrupted while waiting for OAuth callback", e);
        } catch (java.util.concurrent.ExecutionException e) {
            throw new OAuthException("OAuth callback failed: " + e.getCause().getMessage(), e.getCause());
        }
    }

    private void verifyCallback(CallbackResult result, State expectedState) {
        if (result.isError()) {
            String sanitizedError = sanitizeForLog(result.error());
            String sanitizedDescription = sanitizeForLog(result.errorDescription());
            String detail = sanitizedError
                    + (sanitizedDescription != null ? " - " + sanitizedDescription : "");
            error("OAuth callback rejected: authorization server returned error: " + detail);
            throw new OAuthException("Authorization server returned error: " + detail);
        }
        if (result.code() == null) {
            error("OAuth callback rejected: missing authorization code");
            throw new OAuthException("OAuth callback missing authorization code");
        }
        if (!expectedState.getValue().equals(result.state())) {
            error("OAuth callback rejected: state mismatch (possible CSRF)");
            throw new OAuthException("OAuth callback state mismatch (possible CSRF)");
        }
    }

    private OAuthTokens exchangeCodeForTokens(URI mcpResource,
                                               OAuthClientHints hints,
                                               AuthorizationServerMetadata metadata,
                                               ClientCredentials credentials,
                                               AuthorizationCode code,
                                               CodeVerifier verifier,
                                               URI redirectUri) {
        AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, redirectUri, verifier);
        TokenRequest.Builder builder = newTokenRequestBuilder(metadata.getTokenEndpointURI(), credentials, grant);
        if (mcpResource != null) {
            builder.resource(mcpResource);
        }
        Scope resolvedScope = resolveScopes(hints);
        if (resolvedScope != null) {
            builder.scope(resolvedScope);
        }
        OAuthTokens tokens = toOAuthTokens(sendTokenRequest(builder.build()));
        info("Token exchange succeeded");
        return tokens;
    }

    private TokenRequest buildRefreshTokenRequest(AuthorizationServerMetadata metadata,
                                                    String clientId,
                                                    String clientSecret,
                                                    RefreshToken refreshToken,
                                                    URI mcpResource) {
        ClientCredentials credentials = new ClientCredentials(clientId, clientSecret);
        RefreshTokenGrant grant = new RefreshTokenGrant(refreshToken);
        TokenRequest.Builder builder = newTokenRequestBuilder(metadata.getTokenEndpointURI(), credentials, grant);
        if (mcpResource != null) {
            builder.resource(mcpResource);
        }
        return builder.build();
    }

    private TokenRequest.Builder newTokenRequestBuilder(URI tokenEndpoint,
                                                          ClientCredentials credentials,
                                                          com.nimbusds.oauth2.sdk.AuthorizationGrant grant) {
        ClientID clientId = new ClientID(credentials.clientId());
        if (credentials.clientSecret() != null) {
            ClientAuthentication clientAuth = new ClientSecretBasic(clientId, new Secret(credentials.clientSecret()));
            return new TokenRequest.Builder(tokenEndpoint, clientAuth, grant);
        }
        return new TokenRequest.Builder(tokenEndpoint, clientId, grant);
    }

    private TokenResponse sendTokenRequest(TokenRequest request) {
        try {
            HTTPResponse httpResponse = sendWithTimeouts(request.toHTTPRequest());
            return TokenResponse.parse(httpResponse);
        } catch (IOException | com.nimbusds.oauth2.sdk.ParseException e) {
            error("Token exchange failed: " + e.getMessage());
            throw new OAuthException("Token endpoint request failed: " + e.getMessage(), e);
        }
    }

    HTTPRequest applyTimeouts(HTTPRequest httpRequest) {
        httpRequest.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
        httpRequest.setReadTimeout(READ_TIMEOUT_MILLIS);
        return httpRequest;
    }

    private HTTPResponse sendWithTimeouts(HTTPRequest httpRequest) throws IOException {
        HTTPRequest configured = applyTimeouts(httpRequest);
        return configured.send(burpSender);
    }

    private OAuthTokens toOAuthTokens(TokenResponse response) {
        if (!response.indicatesSuccess()) {
            TokenErrorResponse errorResponse = (TokenErrorResponse) response;
            String code = errorResponse.getErrorObject().getCode();
            String description = errorResponse.getErrorObject().getDescription();
            String detail = code + (description != null ? " - " + description : "");
            error("Token exchange failed: " + detail);
            throw new OAuthException("Token endpoint error: " + detail);
        }
        Tokens tokens = response.toSuccessResponse().getTokens();
        AccessToken accessToken = tokens.getAccessToken();
        Instant expiresAt = computeExpiry(accessToken);
        String subject = extractSubject(accessToken);
        return new OAuthTokens(accessToken, tokens.getRefreshToken(), expiresAt, subject);
    }

    private Instant computeExpiry(AccessToken accessToken) {
        long lifetime = accessToken.getLifetime();
        long seconds = lifetime > 0 ? lifetime : 300;
        return Instant.now(clock).plusSeconds(seconds);
    }

    private String extractSubject(AccessToken accessToken) {
        try {
            return JWTParser.parse(accessToken.getValue()).getJWTClaimsSet().getSubject();
        } catch (java.text.ParseException | RuntimeException e) {
            info("Access token subject not extracted (not a JWT or missing 'sub' claim)");
            return null;
        }
    }

    static String sanitizeForLog(String value) {
        if (value == null) {
            return null;
        }
        return value.replaceAll("[\r\n\t]", " ");
    }

    private void info(String message) {
        eventLog.info(message);
    }

    private void warn(String message) {
        eventLog.warn(message);
    }

    private void error(String message) {
        eventLog.error(message);
    }

    private record ClientCredentials(String clientId, String clientSecret,
                                     Optional<String> registrationAccessToken,
                                     Optional<String> registrationClientUri) {
        ClientCredentials(String clientId, String clientSecret) {
            this(clientId, clientSecret, Optional.empty(), Optional.empty());
        }
    }
}
