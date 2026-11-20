package com.mcpscanner.auth.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.auth.oauth.safety.FetchPurpose;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.client.McpDiscoveryClient;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.RecordingRealHttp;
import com.mcpscanner.mcp.McpObjectMapper;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.sun.net.httpserver.HttpServer;
import burp.api.montoya.logging.Logging;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.mock;

class OAuthAuthorizationFlowTest {

    private static final int CONFIGURED_CALLBACK_PORT = 12345;

    private HttpServer authServer;
    private int authPort;

    /**
     * TEST reproduction of the deleted production {@code validatorBackedGate} semantics
     * (loopback-tolerant, private/link-local-rejecting): rejects RFC1918 / link-local hosts but
     * allows {@code http://127.0.0.1} issuers, which the HttpServer-driven tests use. This is NOT
     * the production gate — production uses {@code DefaultSuspiciousDestinationGate}. If
     * {@link OAuthUrlValidator}'s contract changes, this test gate may need updating.
     */
    private static final SuspiciousDestinationGate VALIDATOR_GATE = (url, purpose) -> {
        java.util.Optional<String> classification = new OAuthUrlValidator().classify(url)
                .filter(code -> !code.equals(OAuthUrlValidator.CLASSIFICATION_LOOPBACK) || url.getPort() == 0);
        return classification.isEmpty()
                ? SuspiciousDestinationGate.Decision.allow()
                : SuspiciousDestinationGate.Decision.deny(new SuspiciousDestinationGate.Reason(
                        url, null, List.of(classification.get()), purpose, "validator-rejected " + url));
    };

    @BeforeEach
    void startAuthServer() throws IOException {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        authServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        authPort = authServer.getAddress().getPort();
    }

    /** Canonical flow construction routed through Burp via {@link RecordingRealHttp}. */
    private OAuthAuthorizationFlow newFlow(CallbackListenerFactory listenerFactory,
                                           BrowserLauncher browserLauncher,
                                           Clock clock,
                                           SuspiciousDestinationGate gate,
                                           McpEventLog eventLog) {
        return new OAuthAuthorizationFlow(listenerFactory, browserLauncher, clock, gate,
                eventLog, new RecordingRealHttp());
    }

    private OAuthAuthorizationFlow newFlow(CallbackListenerFactory listenerFactory,
                                           BrowserLauncher browserLauncher,
                                           Clock clock) {
        return newFlow(listenerFactory, browserLauncher, clock, VALIDATOR_GATE, McpEventLog.noop());
    }

    private OAuthAuthorizationFlow newFlow(CallbackListenerFactory listenerFactory,
                                           BrowserLauncher browserLauncher,
                                           Clock clock,
                                           McpEventLog eventLog) {
        return newFlow(listenerFactory, browserLauncher, clock, VALIDATOR_GATE, eventLog);
    }


    /** No-arg-equivalent flow: default factory + desktop launcher, validator gate, routed via Burp. */
    private OAuthAuthorizationFlow newFlow() {
        return newFlow(CallbackListenerFactory.defaultFactory(),
                uri -> { throw new OAuthException("Browser launch disabled in tests"); }, Clock.systemUTC());
    }

    @AfterEach
    void stopAuthServer() {
        if (authServer != null) {
            authServer.stop(0);
        }
    }

    @Test
    void connectsToCimdServerWithoutRegistrationEndpoint() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        URI documentUrl = URI.create("https://client.example/metadata.json");
        EphemeralCallbackListeners listeners = new EphemeralCallbackListeners();
        AtomicReference<URI> authorization = new AtomicReference<>();
        Map<String, String> tokenForm = new HashMap<>();
        RecordingRealHttp http = cimdHttp(documentUrl, () -> "{\"client_id\":\"" + documentUrl
                + "\",\"client_name\":\"Test\",\"redirect_uris\":[\"" + callbackOn(listeners, "/callback") + "\"]}");
        registerTokenEndpoint(tokenForm);
        AtomicInteger catalogRequests = new AtomicInteger();
        authServer.createContext("/mcp", exchange -> {
            if (!"Bearer cimd-token".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                exchange.sendResponseHeaders(401, -1);
                exchange.close();
                return;
            }
            JsonNode request = McpObjectMapper.INSTANCE.readTree(exchange.getRequestBody());
            String method = request.path("method").asText();
            if (method.equals("tools/list")) catalogRequests.incrementAndGet();
            Object result = switch (method) {
                case "server/discover" -> Map.of("supportedVersions", List.of("2026-07-28"), "capabilities", Map.of());
                case "initialize" -> Map.of("protocolVersion", "2026-07-28", "capabilities", Map.of("tools", Map.of()),
                        "serverInfo", Map.of("name", "cimd-fixture", "version", "1"));
                case "tools/list" -> Map.of("tools", List.of(Map.of("name", "safe_tool", "inputSchema", Map.of("type", "object"))));
                default -> throw new IllegalArgumentException(method);
            };
            byte[] bytes = McpObjectMapper.INSTANCE.writeValueAsBytes(Map.of(
                    "jsonrpc", "2.0", "id", request.path("id").asLong(), "result", result));
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
        });
        authServer.start();
        AuthorizationServerMetadata metadata = cimdMetadata(issuer);
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(listeners, uri -> {
            authorization.set(uri);
            deliverCallback(uri);
        }, Clock.systemUTC(), ALLOW_ALL, McpEventLog.noop(), http);
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), null, null, true,
                CONFIGURED_CALLBACK_PORT, Duration.ofSeconds(5), com.mcpscanner.core.oauth.RegistrationMode.AUTO,
                documentUrl);

        List<OAuthSignIn> signIns = new java.util.concurrent.CopyOnWriteArrayList<>();
        flow.addSignInListener(signIns::add);

        URI resource = URI.create(issuer + "/mcp");
        OAuthSession session = flow.connect(resource, hints, metadata);

        assertThat(listeners.requestedPort()).isEqualTo(CONFIGURED_CALLBACK_PORT);
        assertThat(session.registrationMode()).isEqualTo(com.mcpscanner.core.oauth.RegistrationMode.CIMD);
        assertThat(session.clientId()).isEqualTo(documentUrl.toString());
        assertThat(signIns).singleElement().satisfies(signIn -> assertThat(signIn.clientName()).contains("Test"));
        assertThat(parseQuery(authorization.get().getRawQuery())).containsEntry("client_id", documentUrl.toString());
        assertThat(tokenForm).containsEntry("client_id", documentUrl.toString());
        assertThat(http.sentUrls).contains(documentUrl.toString()).noneMatch(url -> url.contains("register"));
        Logging logging = mock(Logging.class);
        McpScannerSession scannerSession = new McpScannerSession(HttpClient.newHttpClient(), McpEventLog.noop());
        try {
            OAuthAuthCodeStrategy auth = new OAuthAuthCodeStrategy(URI.create(issuer),
                    session.clientId(), session.sharedSession(),
                    Clock.systemUTC(), McpEventLog.noop());
            scannerSession.connect(new McpServerConfig(resource.toString(), TransportType.MODERN_HTTP, auth));
            assertThat(new McpDiscoveryClient(scannerSession).discoverTools())
                    .extracting(tool -> tool.name()).containsExactly("safe_tool");
            assertThat(catalogRequests).hasValue(1);
        } finally {
            scannerSession.disconnect();
        }
    }

    @Test
    void rejectsCallbackIssuerMismatchBeforeTokenExchange() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        Map<String, String> tokenForm = new HashMap<>();
        registerTokenEndpoint(tokenForm);
        authServer.start();
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                uri -> deliverCallbackWithIssuer(uri, "https://other.example"), Clock.systemUTC(), ALLOW_ALL,
                McpEventLog.noop(), new RecordingRealHttp());
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), "registered", null, false,
                0, Duration.ofSeconds(5));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example/mcp"), hints, cimdMetadata(issuer)))
                .isInstanceOf(OAuthException.class).hasMessageContaining("issuer mismatch");
        assertThat(tokenForm).isEmpty();
    }

    @Test
    void rejectsPreDiscoveredIssuerMismatchBeforeRegistration() throws Exception {
        AtomicInteger browserOpens = new AtomicInteger();
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                uri -> browserOpens.incrementAndGet(), Clock.systemUTC(), ALLOW_ALL, McpEventLog.noop(), http);
        OAuthClientHints hints = new OAuthClientHints(URI.create("https://expected.example"), List.of(), null,
                null, true, 0, Duration.ofSeconds(5));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example/mcp"), hints,
                cimdMetadata("https://other.example")))
                .isInstanceOf(OAuthException.class).hasMessageContaining("issuer mismatch");
        assertThat(browserOpens).hasValue(0);
        assertThat(http.sentUrls).isEmpty();
    }

    @Test
    void dcrDescribesNativePublicClient() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        AtomicReference<JsonNode> registration = new AtomicReference<>();
        registerMetadataWithRegistration(issuer, "/authorize", "/token", "/register");
        registerTokenEndpoint(new HashMap<>());
        authServer.createContext("/register", exchange -> {
            registration.set(McpObjectMapper.INSTANCE.readTree(exchange.getRequestBody()));
            byte[] bytes = "{\"client_id\":\"native-client\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
        });
        authServer.start();
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), null, null, true, 0,
                Duration.ofSeconds(5));

        flowRoutedThrough(new RecordingRealHttp(), McpEventLog.noop())
                .connect(URI.create("https://mcp.example/mcp"), hints);

        assertThat(registration.get().path("application_type").asText()).isEqualTo("native");
        assertThat(registration.get().path("token_endpoint_auth_method").asText()).isEqualTo("none");
    }

    @Test
    void dcrBodyCarriesConfiguredClientIdentity() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        AtomicReference<JsonNode> registration = new AtomicReference<>();
        registerMetadataWithRegistration(issuer, "/authorize", "/token", "/register");
        registerTokenEndpoint(new HashMap<>());
        authServer.createContext("/register", exchange -> {
            registration.set(McpObjectMapper.INSTANCE.readTree(exchange.getRequestBody()));
            byte[] bytes = "{\"client_id\":\"native-client\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
        });
        authServer.start();
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), null, null, true, 0,
                Duration.ofSeconds(5));
        var identity = com.mcpscanner.config.ClientIdentity.from(java.util.Map.of(
                com.mcpscanner.config.ClientIdentityField.OAUTH_CLIENT_NAME, "Acme Scanner",
                com.mcpscanner.config.ClientIdentityField.CLIENT_URI, "https://acme.example",
                com.mcpscanner.config.ClientIdentityField.LOGO_URI, "https://acme.example/logo.png")::get);

        new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), Clock.systemUTC(), ALLOW_ALL,
                McpEventLog.noop(), new RecordingRealHttp(),
                () -> identity).connect(URI.create("https://mcp.example/mcp"), hints);

        assertThat(registration.get().path("client_name").asText()).isEqualTo("Acme Scanner");
        assertThat(registration.get().path("client_uri").asText()).isEqualTo("https://acme.example");
        assertThat(registration.get().path("logo_uri").asText()).isEqualTo("https://acme.example/logo.png");
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "'{\"client_id\":\"native-client\"}', Acme Scanner",
            "'{\"client_id\":\"native-client\",\"client_name\":\"Renamed by server\"}', Renamed by server"})
    void aDynamicallyRegisteredSignInCarriesTheNameTheServerRegistered(String registered, String expectedName)
            throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadataWithRegistration(issuer, "/authorize", "/token", "/register");
        registerTokenEndpoint(new HashMap<>());
        authServer.createContext("/register", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] bytes = registered.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
        });
        authServer.start();
        var identity = com.mcpscanner.config.ClientIdentity.from(field ->
                field == com.mcpscanner.config.ClientIdentityField.OAUTH_CLIENT_NAME ? "Acme Scanner" : "");
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), Clock.systemUTC(), ALLOW_ALL,
                McpEventLog.noop(), new RecordingRealHttp(), () -> identity);
        List<OAuthSignIn> signIns = new java.util.concurrent.CopyOnWriteArrayList<>();
        flow.addSignInListener(signIns::add);

        flow.connect(URI.create("https://mcp.example/mcp"), new OAuthClientHints(URI.create(issuer), List.of(), null,
                null, true, 0, Duration.ofSeconds(5)));

        assertThat(signIns).singleElement().satisfies(signIn -> assertThat(signIn.clientName()).contains(expectedName));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"client-id", "callback", "private-client", "missing-name"})
    void invalidCimdNeverFallsBackToAdvertisedDcr(String failure) throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        URI location = URI.create("https://client.example/metadata.json");
        EphemeralCallbackListeners listeners = new EphemeralCallbackListeners();
        RecordingRealHttp http = cimdHttp(location, () -> invalidClientDocument(failure, location, listeners));
        AtomicInteger browserOpens = new AtomicInteger();
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(listeners,
                uri -> browserOpens.incrementAndGet(), Clock.systemUTC(), ALLOW_ALL, McpEventLog.noop(), http);
        AuthorizationServerMetadata metadata = cimdMetadata(issuer);
        metadata.setRegistrationEndpointURI(URI.create(issuer + "/register"));
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), null, null, true,
                CONFIGURED_CALLBACK_PORT, Duration.ofSeconds(5), com.mcpscanner.core.oauth.RegistrationMode.AUTO,
                location);

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example/mcp"), hints, metadata))
                .isInstanceOf(OAuthException.class);
        assertThat(browserOpens).hasValue(0);
        assertThat(http.sentUrls).containsExactly(location.toString());
    }

    private static String invalidClientDocument(String failure, URI location, EphemeralCallbackListeners listeners) {
        Map<String, Object> document = new HashMap<>();
        document.put("client_id", location.toString());
        document.put("client_name", "Client");
        document.put("redirect_uris", List.of(callbackOn(listeners, "/callback")));
        switch (failure) {
            case "client-id" -> document.put("client_id", location + "?different");
            case "callback" -> document.put("redirect_uris", List.of(callbackOn(listeners, "/other")));
            case "private-client" -> document.put("token_endpoint_auth_method", "client_secret_basic");
            case "missing-name" -> document.remove("client_name");
        }
        try {
            return McpObjectMapper.INSTANCE.writeValueAsString(document);
        } catch (com.fasterxml.jackson.core.JsonProcessingException unexpected) {
            throw new IllegalStateException(unexpected);
        }
    }

    private static String callbackOn(EphemeralCallbackListeners listeners, String path) {
        return "http://127.0.0.1:" + listeners.boundPort() + path;
    }

    @Test
    void explicitCimdDoesNotFallBackWhenServerOnlyAdvertisesDcr() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.parse(JSONObjectUtils.parse(
                "{\"issuer\":\"" + issuer + "\",\"response_types_supported\":[\"code\"],"
                        + "\"registration_endpoint\":\"" + issuer + "/register\"}"));
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), null, null, true,
                CONFIGURED_CALLBACK_PORT, Duration.ofSeconds(5), com.mcpscanner.core.oauth.RegistrationMode.CIMD,
                URI.create("https://client.example/metadata.json"));

        assertThatThrownBy(() -> flowRoutedThrough(http, McpEventLog.noop(), new EphemeralCallbackListeners())
                .connect(URI.create("https://mcp.example/mcp"), hints, metadata))
                .isInstanceOf(OAuthException.class).hasMessageContaining("unavailable");
        assertThat(http.sentUrls).isEmpty();
    }

    @Test
    void requiresCallbackIssuerWhenServerAdvertisesIt() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        AuthorizationServerMetadata metadata = cimdMetadata(issuer);
        metadata.setSupportsAuthorizationResponseIssuerParam(true);
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), "client", null, false, 0,
                Duration.ofSeconds(5));

        assertThatThrownBy(() -> flowRoutedThrough(http, McpEventLog.noop())
                .connect(URI.create("https://mcp.example/mcp"), hints, metadata))
                .isInstanceOf(OAuthException.class).hasMessageContaining("missing issuer");
        assertThat(http.sentUrls).isEmpty();
    }

    @Test
    void connectsAndRefreshesWhenOnlyOidcMetadataExists() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort + "/tenant";
        registerOidcMetadata("/tenant/.well-known/openid-configuration", issuer);
        Map<String, String> tokenForm = new HashMap<>();
        registerTokenEndpoint(tokenForm, "refresh-token");
        authServer.start();
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthAuthorizationFlow flow = flowRoutedThrough(http, McpEventLog.noop());
        URI resource = URI.create("https://mcp.example/mcp");
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), "client", null, false, 0,
                Duration.ofSeconds(5));

        OAuthSession session = flow.connect(resource, hints);
        OAuthTokens refreshed = session.sharedSession().refresh();

        assertThat(refreshed.accessToken().getValue()).isEqualTo("cimd-token");
        assertThat(tokenForm).containsEntry("grant_type", "refresh_token");
        List<String> expectedRequests = List.of("http://127.0.0.1:" + authPort
                        + "/.well-known/oauth-authorization-server/tenant",
                "http://127.0.0.1:" + authPort + "/.well-known/openid-configuration/tenant",
                issuer + "/.well-known/openid-configuration", "http://127.0.0.1:" + authPort + "/token");
        assertThat(http.sentUrls).containsExactlyElementsOf(java.util.stream.Stream.concat(
                expectedRequests.stream(), java.util.stream.Stream.of("http://127.0.0.1:" + authPort + "/token")).toList());
    }

    @Test
    void rejectsOidcIssuerMismatchWithoutTokenExchangeOrFurtherFallback() throws Exception {
        String origin = "http://127.0.0.1:" + authPort;
        URI issuer = URI.create(origin + "/tenant");
        registerOidcMetadata("/.well-known/openid-configuration/tenant", "https://different.example");
        registerOidcMetadata("/tenant/.well-known/openid-configuration", issuer.toString());
        Map<String, String> tokenForm = new HashMap<>();
        registerTokenEndpoint(tokenForm);
        authServer.start();
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthAuthorizationFlow flow = flowRoutedThrough(http, McpEventLog.noop());
        URI resource = URI.create("https://mcp.example/mcp");
        OAuthClientHints hints = new OAuthClientHints(issuer, List.of(), "client", null, false, 0,
                Duration.ofSeconds(5));

        assertThatThrownBy(() -> flow.connect(resource, hints)).isInstanceOf(OAuthException.class).hasMessageContaining("issuer mismatch");
        assertThat(tokenForm).isEmpty();
        assertThat(http.sentUrls).containsExactly(origin + "/.well-known/oauth-authorization-server/tenant",
                origin + "/.well-known/openid-configuration/tenant");
    }

    private void registerOidcMetadata(String path, String issuer) throws Exception {
        String origin = "http://127.0.0.1:" + authPort;
        String body = "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\"" + origin
                + "/authorize\",\"token_endpoint\":\"" + origin + "/token\",\"response_types_supported\":[\"code\"]}";
        authServer.createContext(path, exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
        });
    }

    @Test
    void rejectsInvalidStateBeforeDisplayingAuthorizationError() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        McpEventLog log = new McpEventLog(null);
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(), uri -> {
            Map<String, String> params = parseQuery(uri.getRawQuery());
            try {
                HttpClient.newHttpClient().send(HttpRequest.newBuilder().uri(URI.create(params.get("redirect_uri")
                        + "?error=access_denied&error_description=untrusted-error-marker&state=wrong"))
                        .GET().build(), HttpResponse.BodyHandlers.discarding());
            } catch (Exception e) { throw new RuntimeException(e); }
        }, Clock.systemUTC(), ALLOW_ALL, log, new RecordingRealHttp());
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), "client", null, false, 0,
                Duration.ofSeconds(5));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example/mcp"), hints, cimdMetadata(issuer)))
                .isInstanceOf(OAuthException.class).hasMessageContaining("state mismatch")
                .hasMessageNotContaining("untrusted-error-marker");
        assertThat(log.snapshot()).noneMatch(entry -> entry.message().contains("untrusted-error-marker"));
    }

    private static void deliverCallbackWithIssuer(URI authorizeUri, String issuer) {
        Map<String, String> params = parseQuery(authorizeUri.getRawQuery());
        try {
            HttpClient.newHttpClient().send(HttpRequest.newBuilder().uri(URI.create(params.get("redirect_uri")
                    + "?code=auth-code&state=" + URLEncoder.encode(params.get("state"), StandardCharsets.UTF_8)
                    + "&iss=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8))).GET().build(),
                    HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private RecordingRealHttp cimdHttp(URI documentUrl, java.util.function.Supplier<String> document) {
        return new RecordingRealHttp() {
            @Override
            public burp.api.montoya.http.message.HttpRequestResponse sendRequest(
                    burp.api.montoya.http.message.requests.HttpRequest request,
                    burp.api.montoya.http.RequestOptions options) {
                if (request.url().equals(documentUrl.toString())) {
                    sentUrls.add(request.url());
                    return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request,
                            burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + document.get()));
                }
                return super.sendRequest(request, options);
            }
        };
    }

    private AuthorizationServerMetadata cimdMetadata(String issuer) throws Exception {
        return AuthorizationServerMetadata.parse(JSONObjectUtils.parse("{\"issuer\":\"" + issuer
                + "\",\"authorization_endpoint\":\"" + issuer + "/authorize\",\"token_endpoint\":\"" + issuer
                + "/token\",\"response_types_supported\":[\"code\"],\"client_id_metadata_document_supported\":true}"));
    }

    private void registerTokenEndpoint(Map<String, String> tokenForm) {
        registerTokenEndpoint(tokenForm, null);
    }

    private void registerTokenEndpoint(Map<String, String> tokenForm, String refreshToken) {
        authServer.createContext("/token", exchange -> {
            tokenForm.putAll(parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            String refresh = refreshToken == null ? "" : ",\"refresh_token\":\"" + refreshToken + "\"";
            byte[] bytes = ("{\"access_token\":\"cimd-token\",\"token_type\":\"Bearer\"" + refresh + "}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
        });
    }

    @Test
    void connectWarnsWhenTheAuthorizationServerWithholdsRequestedScopes() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] bytes = "{\"access_token\":\"acc-1\",\"token_type\":\"Bearer\",\"scope\":\"read\"}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();
        McpEventLog log = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), Clock.systemUTC(), log);

        flow.connect(URI.create("https://mcp.example.com/mcp"), new OAuthClientHints(URI.create(issuer),
                List.of("read", "write"), "client-test", null, false, 0, Duration.ofSeconds(10)));

        assertThat(log.snapshot()).anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                && entry.message().equals("Authorization server granted read but withheld write; tools needing "
                        + "write will fail. Reconnect as a user allowed write to test them."));
    }

    @Test
    void connectTellsSignInListenersWhoSignedInAndWithWhichClient() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] bytes = "{\"access_token\":\"acc-1\",\"token_type\":\"Bearer\",\"scope\":\"read\"}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();
        com.mcpscanner.config.ClientIdentity identity = com.mcpscanner.config.ClientIdentity.from(field -> switch (field) {
            case OAUTH_CLIENT_NAME -> "Configured name";
            case SOFTWARE_ID -> "scanner-software";
            default -> "";
        });
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), Clock.systemUTC(), VALIDATOR_GATE,
                McpEventLog.noop(), new RecordingRealHttp(), () -> identity);
        List<OAuthSignIn> signIns = new java.util.concurrent.CopyOnWriteArrayList<>();
        flow.addSignInListener(signIns::add);

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), new OAuthClientHints(
                URI.create(issuer), List.of("read", "write"), "client-test", null, false, 0, Duration.ofSeconds(10)));

        assertThat(signIns).singleElement().satisfies(signIn -> {
            assertThat(signIn.issuer()).isEqualTo(URI.create(issuer));
            assertThat(signIn.authorizationEndpoint()).isEqualTo(URI.create(issuer + "/authorize"));
            assertThat(signIn.registrationEndpoint()).isEmpty();
            assertThat(signIn.clientId()).isEqualTo("client-test");
            assertThat(signIn.clientName()).isEmpty();
            assertThat(signIn.redirectUri().toString()).startsWith("http://127.0.0.1:").endsWith("/callback");
            assertThat(signIn.grantedScopes()).containsExactly("read");
            assertThat(signIn.softwareId()).contains("scanner-software");
            assertThat(signIn.resource()).isEqualTo(URI.create("https://mcp.example.com/mcp"));
        });
        assertThat(session.clientId()).isEqualTo("client-test");
    }

    @Test
    void connectHandsSignInListenersTheClientSecretItAuthenticatedWithButNeverPrintsIt() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] bytes = "{\"access_token\":\"acc-1\",\"token_type\":\"Bearer\",\"scope\":\"read\"}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), Clock.systemUTC(), VALIDATOR_GATE,
                McpEventLog.noop(), new RecordingRealHttp());
        List<OAuthSignIn> signIns = new java.util.concurrent.CopyOnWriteArrayList<>();
        flow.addSignInListener(signIns::add);

        flow.connect(URI.create("https://mcp.example.com/mcp"), new OAuthClientHints(URI.create(issuer),
                List.of("read"), "client-test", "connect-secret", false, 0, Duration.ofSeconds(10)));

        assertThat(signIns).singleElement().satisfies(signIn -> {
            assertThat(signIn.clientSecret()).contains("connect-secret");
            assertThat(signIn.toString()).doesNotContain("connect-secret");
            assertThat(signIn.withGrantedScopes(java.util.Set.of("read", "write")).clientSecret()).contains("connect-secret");
        });
    }

    @Test
    void aFailingSignInListenerDoesNotFailConnect() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        registerTokenEndpoint(new HashMap<>());
        authServer.start();
        McpEventLog log = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), Clock.systemUTC(), log);
        flow.addSignInListener(signIn -> {
            throw new IllegalStateException("listener broke");
        });

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0, Duration.ofSeconds(10)));

        assertThat(session.clientId()).isEqualTo("client-test");
        assertThat(log.snapshot()).anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                && entry.message().contains("listener broke"));
    }

    @Test
    void aFailedSignInTellsNoSignInListener() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        Map<String, String> tokenForm = new HashMap<>();
        registerTokenEndpoint(tokenForm);
        authServer.start();
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                uri -> deliverCallbackWithIssuer(uri, "https://other.example"), Clock.systemUTC(), ALLOW_ALL,
                McpEventLog.noop(), new RecordingRealHttp());
        List<OAuthSignIn> signIns = new java.util.concurrent.CopyOnWriteArrayList<>();
        flow.addSignInListener(signIns::add);
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), "registered", null, false,
                0, Duration.ofSeconds(5));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example/mcp"), hints, cimdMetadata(issuer)))
                .isInstanceOf(OAuthException.class);
        assertThat(signIns).isEmpty();
    }

    @Test
    void connectExchangesAuthorizationCodeForTokens() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String tokenPath = "/token";
        String authPath = "/authorize";

        Map<String, String> capturedTokenForm = new HashMap<>();
        AtomicReference<URI> launchedUri = new AtomicReference<>();

        registerMetadata(issuer, authPath, tokenPath);
        authServer.createContext(tokenPath, exchange -> {
            String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            capturedTokenForm.putAll(parseForm(form));
            String body = "{\"access_token\":\"acc-1\",\"token_type\":\"Bearer\",\"expires_in\":300,"
                    + "\"refresh_token\":\"ref-1\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> {
                    launchedUri.set(uri);
                    new Thread(() -> deliverCallback(uri)).start();
                },
                Clock.systemUTC());

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer),
                List.of("read", "write"),
                "client-test",
                null,
                false,
                0,
                Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("acc-1");
        assertThat(session.registrationMode()).isEqualTo(com.mcpscanner.core.oauth.RegistrationMode.PRE_REGISTERED);
        assertThat(session.tokens().refreshToken().getValue()).isEqualTo("ref-1");
        assertThat(session.clientId()).isEqualTo("client-test");
        assertThat(launchedUri.get().toString()).contains("response_type=code");
        assertThat(launchedUri.get().toString()).contains("code_challenge_method=S256");
        assertThat(launchedUri.get().toString()).contains("client_id=client-test");
        assertThat(launchedUri.get().toString()).contains("resource=");
        assertThat(capturedTokenForm).containsEntry("grant_type", "authorization_code");
        assertThat(capturedTokenForm).containsKey("code_verifier");
        assertThat(capturedTokenForm).containsEntry("client_id", "client-test");
    }

    /**
     * When pre-discovered AS metadata is supplied the flow skips the Nimbus well-known re-fetch
     * entirely. The well-known endpoint is registered to return 404 here — if the fix is absent
     * the flow would throw; if present it succeeds.
     */
    @Test
    void connectWithPreDiscoveredMetadataSkipsMetadataFetch() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String tokenPath = "/token";
        String authPath = "/authorize";

        AtomicReference<URI> launchedUri = new AtomicReference<>();

        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            exchange.sendResponseHeaders(404, 0);
            exchange.getResponseBody().close();
        });
        authServer.createContext(tokenPath, exchange -> {
            String body = "{\"access_token\":\"pre-disc-token\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref-pre\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        String metadataJson = "{"
                + "\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + authPath + "\","
                + "\"token_endpoint\":\"" + issuer + tokenPath + "\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
                + "\"code_challenge_methods_supported\":[\"S256\"]"
                + "}";
        AuthorizationServerMetadata preDiscovered = AuthorizationServerMetadata.parse(
                JSONObjectUtils.parse(metadataJson));

        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> {
                    launchedUri.set(uri);
                    new Thread(() -> deliverCallback(uri)).start();
                },
                Clock.systemUTC());

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer),
                List.of(),
                "client-prebuilt",
                null,
                false,
                0,
                Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints, preDiscovered);

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("pre-disc-token");
        assertThat(session.clientId()).isEqualTo("client-prebuilt");
    }

    @Test
    void connectWithDcrReturnsRegisteredClientIdNotJwtSubject() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String tokenPath = "/token";
        String authPath = "/authorize";
        String registrationPath = "/register";
        String registeredClientId = "dcr-registered-client";
        String jwtSubject = "user-alice";

        AtomicReference<URI> launchedUri = new AtomicReference<>();

        registerMetadataWithRegistration(issuer, authPath, tokenPath, registrationPath);
        authServer.createContext(registrationPath, exchange -> {
            String body = "{"
                    + "\"client_id\":\"" + registeredClientId + "\","
                    + "\"client_id_issued_at\":1700000000,"
                    + "\"redirect_uris\":[\"http://localhost:0/callback\"],"
                    + "\"token_endpoint_auth_method\":\"none\","
                    + "\"grant_types\":[\"authorization_code\",\"refresh_token\"],"
                    + "\"response_types\":[\"code\"]"
                    + "}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.createContext(tokenPath, exchange -> {
            String header = "{\"alg\":\"none\"}";
            String payload = "{\"sub\":\"" + jwtSubject + "\"}";
            String fakeJwt = base64Url(header) + "." + base64Url(payload) + ".";
            String body = "{\"access_token\":\"" + fakeJwt + "\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref-dcr\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> {
                    launchedUri.set(uri);
                    new Thread(() -> deliverCallback(uri)).start();
                },
                Clock.systemUTC());

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer),
                List.of(),
                null,
                null,
                true,
                0,
                Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.clientId()).isEqualTo(registeredClientId);
        assertThat(session.clientId()).isNotEqualTo(jwtSubject);
        assertThat(session.tokens().subject()).isEqualTo(jwtSubject);
        SignInEvidence evidence = session.sharedSession().signInEvidence();
        assertThat(evidence.registrationResponseJson()).hasValueSatisfying(json ->
                assertThat(json).contains("\"client_id\":\"" + registeredClientId + "\""));
        assertThat(evidence.authorizationServerMetadataJson()).contains("\"token_endpoint\"", tokenPath);
    }

    @Test
    void dcrErrorMessageIncludesStatusWhenBodyIsEmpty() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String registrationPath = "/register";

        registerMetadataWithRegistration(issuer, "/authorize", "/token", registrationPath);
        authServer.createContext(registrationPath, exchange -> {
            exchange.sendResponseHeaders(400, -1);
            exchange.close();
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), null, null, true, 0, Duration.ofSeconds(10));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"), hints))
                .isInstanceOf(DcrUnsupportedException.class)
                .hasMessageContaining("HTTP 400");

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("DCR registration failed: HTTP 400"));
    }

    @Test
    void dcrErrorMessageRetainsStatusWithoutUntrustedCodeOrDescription() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String registrationPath = "/register";

        registerMetadataWithRegistration(issuer, "/authorize", "/token", registrationPath);
        authServer.createContext(registrationPath, exchange -> {
            String body = "{\"error\":\"invalid_client_metadata\","
                    + "\"error_description\":\"redirect_uri not registered\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(400, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), null, null, true, 0, Duration.ofSeconds(10));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"), hints))
                .isInstanceOf(DcrUnsupportedException.class);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("DCR registration failed")
                        && entry.message().contains("HTTP 400"));
        assertThat(eventLog.snapshot()).noneMatch(entry -> entry.message().contains("invalid_client_metadata")
                || entry.message().contains("redirect_uri not registered"));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("untrustedRegistrationResponses")
    void dcrFailureNeverExposesUntrustedResponseFields(int status, String response) throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadataWithRegistration(issuer, "/authorize", "/token", "/register");
        authServer.createContext("/register", exchange -> {
            byte[] body = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        authServer.start();
        McpEventLog log = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(), uri -> {}, Clock.systemUTC(), log);
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(), null, null,
                true, 0, Duration.ofSeconds(10));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example/mcp"), hints))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("HTTP " + status)
                .hasMessageNotContaining("secret-marker")
                .hasNoCause();
        assertThat(log.snapshot()).noneMatch(entry -> entry.message().contains("secret-marker"));
        assertThat(log.snapshot()).allSatisfy(entry -> assertThat(entry.throwable()).isNull());
    }

    private static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> untrustedRegistrationResponses() {
        return java.util.stream.Stream.of(
                org.junit.jupiter.params.provider.Arguments.of(400,
                        "{\"error\":\"secret-marker-code\",\"error_description\":\"secret-marker-description\",\"client_secret\":\"secret-marker-token\"}"),
                org.junit.jupiter.params.provider.Arguments.of(400, "secret-marker-body {"),
                org.junit.jupiter.params.provider.Arguments.of(201,
                        "{\"client_secret\":\"secret-marker-token\",\"client_id\":[]}"));
    }

    @Test
    void dcrConnectionFailureUsesFixedDiagnostic() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String registrationPath = "/register";
        registerMetadataWithRegistration(issuer, "/authorize", "/token", registrationPath);
        authServer.createContext(registrationPath, exchange -> {
            // Close the exchange's TCP connection without sending any response bytes —
            // forces a Nimbus IOException/ParseException through the catch block.
            exchange.close();
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow loggingFlow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), null, null, true, 0, Duration.ofSeconds(10));

        assertThatThrownBy(() -> loggingFlow.connect(URI.create("https://mcp.example.com/mcp"), hints))
                .isInstanceOf(OAuthException.class);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().startsWith("DCR registration failed: ")
                        && !entry.message().endsWith(": null"));
    }

    @Test
    void connectWithDcrCapturesRegistrationCredentials() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String registrationPath = "/register";
        String registeredClientId = "dcr-client-789";
        String registrationToken = "reg-token-abc";
        String registrationUri = issuer + "/register/" + registeredClientId;

        registerMetadataWithRegistration(issuer, "/authorize", "/token", registrationPath);
        authServer.createContext(registrationPath, exchange -> {
            String body = "{"
                    + "\"client_id\":\"" + registeredClientId + "\","
                    + "\"client_id_issued_at\":1700000000,"
                    + "\"registration_access_token\":\"" + registrationToken + "\","
                    + "\"registration_client_uri\":\"" + registrationUri + "\","
                    + "\"redirect_uris\":[\"http://localhost:0/callback\"],"
                    + "\"token_endpoint_auth_method\":\"none\","
                    + "\"grant_types\":[\"authorization_code\",\"refresh_token\"],"
                    + "\"response_types\":[\"code\"]"
                    + "}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc-dcr\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref-dcr\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC());

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer),
                List.of(),
                null,
                null,
                true,
                0,
                Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.clientId()).isEqualTo(registeredClientId);
        assertThat(session.registrationMode()).isEqualTo(com.mcpscanner.core.oauth.RegistrationMode.DCR);
        assertThat(session.registrationAccessToken()).isPresent()
                .hasValue(registrationToken);
        assertThat(session.registrationClientUri()).isPresent()
                .hasValue(registrationUri);
    }

    @Test
    void connectRegistersDcrRedirectUriUsingBoundListenerPort_whenHintsRequestEphemeralPort() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String registrationPath = "/register";
        String registeredClientId = "dcr-port-binding-client";

        AtomicReference<String> capturedRegistrationBody = new AtomicReference<>();
        AtomicReference<URI> launchedUri = new AtomicReference<>();
        AtomicInteger boundListenerPort = new AtomicInteger();

        registerMetadataWithRegistration(issuer, "/authorize", "/token", registrationPath);
        authServer.createContext(registrationPath, exchange -> {
            capturedRegistrationBody.set(
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            String body = "{"
                    + "\"client_id\":\"" + registeredClientId + "\","
                    + "\"client_id_issued_at\":1700000000,"
                    + "\"redirect_uris\":[\"http://localhost:0/callback\"],"
                    + "\"token_endpoint_auth_method\":\"none\","
                    + "\"grant_types\":[\"authorization_code\",\"refresh_token\"],"
                    + "\"response_types\":[\"code\"]"
                    + "}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc-bind\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref-bind\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        CallbackListenerFactory portCapturingFactory = (host, port, path) -> {
            CallbackListener listener = CallbackListener.start(host, port, path);
            boundListenerPort.set(listener.port());
            return listener;
        };

        OAuthAuthorizationFlow flow = newFlow(
                portCapturingFactory,
                uri -> {
                    launchedUri.set(uri);
                    new Thread(() -> deliverCallback(uri)).start();
                },
                Clock.systemUTC());

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer),
                List.of(),
                null,
                null,
                true,
                0,
                Duration.ofSeconds(10));

        flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(capturedRegistrationBody.get())
                .as("DCR registration request body must have been captured")
                .isNotNull();

        JsonNode root = McpObjectMapper.INSTANCE.readTree(capturedRegistrationBody.get());
        String registeredRedirectUri = root.path("redirect_uris").get(0).asText();

        int actualBoundPort = boundListenerPort.get();
        assertThat(actualBoundPort)
                .as("listener should bind a real OS-assigned port, not 0")
                .isGreaterThan(0);

        assertThat(registeredRedirectUri)
                .as("DCR redirect_uri must use the IPv4 loopback literal (matching the bound host) "
                        + "and the bound listener port, not the hinted ephemeral 0")
                .isEqualTo("http://127.0.0.1:" + actualBoundPort + "/callback");

        Map<String, String> launchedQuery = parseQuery(launchedUri.get().getRawQuery());
        assertThat(launchedQuery.get("redirect_uri"))
                .as("authorization request redirect_uri must use the IPv4 loopback literal "
                        + "(matching the bound host) and the bound listener port")
                .isEqualTo("http://127.0.0.1:" + actualBoundPort + "/callback");
    }

    @Test
    void connectWithoutDcrHasEmptyRegistrationCredentials() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC());

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer),
                List.of(),
                "manual-client",
                null,
                false,
                0,
                Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.registrationAccessToken()).isEmpty();
        assertThat(session.registrationClientUri()).isEmpty();
    }

    private static String base64Url(String value) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private void registerMetadataWithRegistration(String issuer,
                                                  String authPath,
                                                  String tokenPath,
                                                  String registrationPath) {
        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            String body = "{"
                    + "\"issuer\":\"" + issuer + "\","
                    + "\"authorization_endpoint\":\"" + issuer + authPath + "\","
                    + "\"token_endpoint\":\"" + issuer + tokenPath + "\","
                    + "\"registration_endpoint\":\"" + issuer + registrationPath + "\","
                    + "\"response_types_supported\":[\"code\"],"
                    + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
                    + "\"code_challenge_methods_supported\":[\"S256\"]"
                    + "}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
    }

    @Test
    void approvedScopeStepUpReopensOriginalCallbackAfterInitialConnectHasClosedIt() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        URI resource = URI.create("https://mcp.example/mcp");
        registerMetadata(issuer, "/authorize", "/token");
        AtomicInteger exchanges = new AtomicInteger();
        authServer.createContext("/token", exchange -> {
            int count = exchanges.incrementAndGet();
            byte[] bytes = ("{\"access_token\":\"access-" + count
                    + "\",\"refresh_token\":\"refresh-" + count
                    + "\",\"token_type\":\"Bearer\",\"expires_in\":300}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();
        List<String> redirects = new java.util.ArrayList<>();
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(), uri -> {
            redirects.add(parseQuery(uri.getRawQuery()).get("redirect_uri"));
            deliverCallback(uri);
        }, Clock.systemUTC());
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of("read"),
                "client-test", null, false, 0, Duration.ofSeconds(2));
        OAuthSession session = flow.connect(resource, hints);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(URI.create(issuer),
                session.clientId(), session.sharedSession(),
                Clock.systemUTC(), McpEventLog.noop(), ignored ->
                com.mcpscanner.core.oauth.AuthorizationApproval.APPROVED);
        var challenge = new com.mcpscanner.core.protocol.McpFlow.HttpResponse(403,
                Map.of("WWW-Authenticate", "Bearer error=\"insufficient_scope\", scope=\"write\""), "", false);

        assertThat(strategy.sharedCredentialProvider().orElseThrow().beginOperation("tools/list").recover(challenge))
                .isEqualTo(com.mcpscanner.core.connection.RecoveryResult.RETRY);
        assertThat(redirects).hasSize(2);
        assertThat(redirects.get(1)).isEqualTo(redirects.get(0));
        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer access-2");
        assertThat(exchanges).hasValue(2);
    }

    @Test
    void anApprovedScopeStepUpTellsSignInListenersTheWidenedGrant() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        AtomicInteger exchanges = new AtomicInteger();
        authServer.createContext("/token", exchange -> {
            String scope = exchanges.incrementAndGet() == 1 ? "read" : "read write";
            byte[] bytes = ("{\"access_token\":\"access\",\"token_type\":\"Bearer\",\"scope\":\"" + scope + "\"}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(),
                OAuthAuthorizationFlowTest::deliverCallback, Clock.systemUTC());
        List<OAuthSignIn> widened = new java.util.concurrent.CopyOnWriteArrayList<>();
        flow.addSignInListener(new SignInListener() {
            @Override
            public void signedIn(OAuthSignIn signIn) {
            }

            @Override
            public void scopesWidened(OAuthSignIn signIn) {
                widened.add(signIn);
            }
        });
        OAuthSession session = flow.connect(URI.create("https://mcp.example/mcp"), new OAuthClientHints(
                URI.create(issuer), List.of("read"), "client-test", null, false, 0, Duration.ofSeconds(2)));
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(URI.create(issuer), session.clientId(),
                session.sharedSession(), Clock.systemUTC(), McpEventLog.noop(),
                ignored -> com.mcpscanner.core.oauth.AuthorizationApproval.APPROVED);
        var challenge = new com.mcpscanner.core.protocol.McpFlow.HttpResponse(403,
                Map.of("WWW-Authenticate", "Bearer error=\"insufficient_scope\", scope=\"write\""), "", false);

        strategy.sharedCredentialProvider().orElseThrow().beginOperation("tools/call").recover(challenge);

        assertThat(widened).singleElement().satisfies(signIn -> {
            assertThat(signIn.clientId()).isEqualTo("client-test");
            assertThat(signIn.grantedScopes()).containsExactlyInAnyOrder("read", "write");
        });
    }

    @Test
    void connectedSharedSessionRetainsRotatedRefreshTokenAndResourceBinding() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        URI resource = URI.create("https://mcp.example/mcp");
        registerMetadata(issuer, "/authorize", "/token");
        java.util.List<Map<String, String>> requests = new java.util.ArrayList<>();
        authServer.createContext("/token", exchange -> {
            requests.add(parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            String refresh = requests.size() == 1 ? ",\"refresh_token\":\"original-refresh\""
                    : requests.size() == 2 ? ",\"refresh_token\":\"rotated-refresh\"" : "";
            byte[] body = ("{\"access_token\":\"access-" + requests.size()
                    + "\",\"token_type\":\"Bearer\",\"expires_in\":300" + refresh + "}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        authServer.start();
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), Clock.systemUTC(), VALIDATOR_GATE,
                McpEventLog.noop(), http);
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of("read"),
                "client-test", null, false, 0, Duration.ofSeconds(10));

        OAuthSession session = flow.connect(resource, hints);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(URI.create(issuer),
                session.clientId(), session.sharedSession(),
                Clock.systemUTC(), McpEventLog.noop());
        var provider = strategy.sharedCredentialProvider().orElseThrow();
        var challenge = new com.mcpscanner.core.protocol.McpFlow.HttpResponse(403,
                Map.of("WWW-Authenticate", "Bearer error=\"insufficient_scope\", scope=\"admin\""), "", false);
        assertThat(provider.beginOperation("tools/list").recover(challenge))
                .isEqualTo(com.mcpscanner.core.connection.RecoveryResult.APPROVAL_REQUIRED);
        assertThat(requests).hasSize(1);
        assertThat(provider.headers()).containsEntry("Authorization", "Bearer access-1");
        assertThat(strategy.refresh()).isTrue();
        assertThat(strategy.refreshToken().getValue()).isEqualTo("rotated-refresh");
        assertThat(provider.headers()).containsEntry("Authorization", "Bearer access-2");
        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer access-2");
        assertThat(session.sharedSession().refresh().refreshToken().getValue()).isEqualTo("rotated-refresh");

        assertThat(requests).hasSize(3).allSatisfy(form -> assertThat(form).containsEntry("resource", resource.toString()));
        assertThat(requests.get(1)).containsEntry("refresh_token", "original-refresh");
        assertThat(requests.get(2)).containsEntry("refresh_token", "rotated-refresh");
        assertThat(http.sentMethodsByUrlSuffix("/token")).containsExactly("POST", "POST", "POST");
    }

    @Test
    void scannerCredentialProviderRefreshesAtThirtySecondBoundaryAndHonorsForced401() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        URI resource = URI.create("https://mcp.example/mcp");
        registerMetadata(issuer, "/authorize", "/token");
        AtomicInteger calls = new AtomicInteger();
        authServer.createContext("/token", exchange -> {
            int call = calls.incrementAndGet();
            byte[] body = ("{\"access_token\":\"access-" + call
                    + "\",\"refresh_token\":\"refresh-" + call
                    + "\",\"token_type\":\"Bearer\",\"expires_in\":300}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        authServer.start();
        MutableClock clock = new MutableClock();
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), clock, VALIDATOR_GATE,
                McpEventLog.noop(), http);
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(),
                "client-test", null, false, 0, Duration.ofSeconds(10));
        OAuthSession session = flow.connect(resource, hints);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(URI.create(issuer),
                session.clientId(), session.sharedSession(),
                clock, McpEventLog.noop());
        var provider = strategy.sharedCredentialProvider().orElseThrow();

        clock.advance(Duration.ofSeconds(269));
        assertThat(provider.headers()).containsEntry("Authorization", "Bearer access-1");
        clock.advance(Duration.ofSeconds(1));
        assertThat(provider.headers()).containsEntry("Authorization", "Bearer access-2");
        var rejected = new com.mcpscanner.core.protocol.McpFlow.HttpResponse(401, Map.of(), "", false);
        assertThat(provider.beginOperation("tools/list").recover(rejected))
                .isEqualTo(com.mcpscanner.core.connection.RecoveryResult.RETRY);
        assertThat(provider.headers()).containsEntry("Authorization", "Bearer access-3");
        assertThat(strategy.refreshToken().getValue()).isEqualTo("refresh-3");
        assertThat(http.sentMethodsByUrlSuffix("/token")).containsExactly("POST", "POST", "POST");
    }

    @Test
    void scannerCredentialProviderStopsAfterThreeFailedProactiveRefreshes() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        URI resource = URI.create("https://mcp.example/mcp");
        registerMetadata(issuer, "/authorize", "/token");
        AtomicInteger calls = new AtomicInteger();
        authServer.createContext("/token", exchange -> {
            boolean initial = calls.incrementAndGet() == 1;
            byte[] body = (initial
                    ? "{\"access_token\":\"initial\",\"refresh_token\":\"refresh\",\"token_type\":\"Bearer\",\"expires_in\":300}"
                    : "{\"error\":\"invalid_grant\",\"error_description\":\"secret-marker\"}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(initial ? 200 : 400, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        authServer.start();
        MutableClock clock = new MutableClock();
        McpEventLog log = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), clock, log);
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(),
                "client-test", null, false, 0, Duration.ofSeconds(10));
        OAuthSession session = flow.connect(resource, hints);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(URI.create(issuer),
                session.clientId(), session.sharedSession(), clock, log);
        AtomicInteger notifications = new AtomicInteger();
        strategy.setTerminalFailureListener(notifications::incrementAndGet);
        var provider = strategy.sharedCredentialProvider().orElseThrow();
        clock.advance(Duration.ofSeconds(270));

        assertThat(provider.headers()).containsEntry("Authorization", "Bearer initial");
        assertThat(provider.headers()).containsEntry("Authorization", "Bearer initial");
        assertThatThrownBy(provider::headers).isInstanceOf(OAuthException.class).hasMessageContaining("reconnect");
        assertThatThrownBy(provider::headers).isInstanceOf(OAuthException.class);
        var rejected = new com.mcpscanner.core.protocol.McpFlow.HttpResponse(401, Map.of(), "", false);
        assertThatThrownBy(() -> provider.beginOperation("tools/list").recover(rejected))
                .isInstanceOf(OAuthException.class);
        assertThat(strategy.isTerminallyFailed()).isTrue();
        assertThat(calls).hasValue(4);
        assertThat(notifications).hasValue(1);
        assertThat(log.snapshot()).noneMatch(entry -> entry.message().contains("secret-marker"));
    }

    private static final class MutableClock extends Clock {
        private java.time.Instant now = java.time.Instant.parse("2026-01-01T00:00:00Z");

        void advance(Duration duration) { now = now.plus(duration); }
        @Override public java.time.ZoneId getZone() { return java.time.ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return Clock.fixed(now, zone); }
        @Override public java.time.Instant instant() { return now; }
    }

    @Test
    void tokenFailureDoesNotExposeUntrustedResponseDetails() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            byte[] body = "{\"error\":\"invalid_grant\",\"error_description\":\"secret-response-marker\"}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(400, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        authServer.start();
        McpEventLog log = new McpEventLog(mock(Logging.class));
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), Clock.systemUTC(), log);
        OAuthClientHints hints = new OAuthClientHints(URI.create(issuer), List.of(),
                "client-test", null, false, 0, Duration.ofSeconds(10));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example/mcp"), hints))
                .isInstanceOf(OAuthException.class)
                .hasMessageNotContaining("secret-response-marker");
        assertThat(log.snapshot()).noneMatch(entry -> entry.message().contains("secret-response-marker"));
    }

    @Test
    void refreshRequestIncludesResourceParam() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String tokenPath = "/token";
        URI mcpResource = URI.create("https://mcp.example.com/mcp");
        Map<String, String> capturedTokenForm = new HashMap<>();
        registerMetadata(issuer, "/authorize", tokenPath);
        authServer.createContext(tokenPath, exchange -> {
            String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            capturedTokenForm.putAll(parseForm(form));
            String body = "{\"access_token\":\"acc-r\",\"token_type\":\"Bearer\",\"expires_in\":600,"
                    + "\"refresh_token\":\"ref-r\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        OAuthAuthorizationFlow flow = flowRoutedThrough(new RecordingRealHttp(), McpEventLog.noop());
        OAuthSession session = flow.connect(mcpResource, new OAuthClientHints(URI.create(issuer), List.of(),
                "client-test", null, false, 0, Duration.ofSeconds(5)));

        session.sharedSession().refresh();

        assertThat(capturedTokenForm).containsEntry("resource", mcpResource.toString())
                .containsEntry("grant_type", "refresh_token").containsEntry("refresh_token", "ref-r");
    }

    @Test
    void connectOmitsScopeParamWhenHintsScopesEmpty() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String tokenPath = "/token";
        String authPath = "/authorize";

        AtomicReference<URI> launchedUri = new AtomicReference<>();

        registerMetadataWithScopes(issuer, authPath, tokenPath, List.of("read", "write"));
        authServer.createContext(tokenPath, exchange -> {
            String body = "{\"access_token\":\"acc-fb\",\"token_type\":\"Bearer\",\"expires_in\":300,"
                    + "\"refresh_token\":\"ref-fb\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> {
                    launchedUri.set(uri);
                    new Thread(() -> deliverCallback(uri)).start();
                },
                Clock.systemUTC());

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer),
                List.of(),
                "client-test",
                null,
                false,
                0,
                Duration.ofSeconds(10));

        flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        Map<String, String> query = parseQuery(launchedUri.get().getRawQuery());
        assertThat(query).doesNotContainKey("scope");
    }

    @Test
    void connectUsesUserScopesWhenProvided() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String tokenPath = "/token";
        String authPath = "/authorize";

        AtomicReference<URI> launchedUri = new AtomicReference<>();

        registerMetadataWithScopes(issuer, authPath, tokenPath, List.of("foo", "bar"));
        authServer.createContext(tokenPath, exchange -> {
            String body = "{\"access_token\":\"acc-u\",\"token_type\":\"Bearer\",\"expires_in\":300,"
                    + "\"refresh_token\":\"ref-u\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> {
                    launchedUri.set(uri);
                    new Thread(() -> deliverCallback(uri)).start();
                },
                Clock.systemUTC());

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer),
                List.of("user_scope"),
                "client-test",
                null,
                false,
                0,
                Duration.ofSeconds(10));

        flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        Map<String, String> query = parseQuery(launchedUri.get().getRawQuery());
        assertThat(query.get("scope")).isEqualTo("user_scope");
        assertThat(query.get("scope")).doesNotContain("foo").doesNotContain("bar");
    }

    @Test
    void connectThrowsWhenIssuerMissing() {
        OAuthAuthorizationFlow flow = newFlow();
        OAuthClientHints hints = new OAuthClientHints(
                null, List.of(), "id", null, false, 0, Duration.ofSeconds(2));

        assertThatThrownBy(() -> flow.connect(URI.create("https://x"), hints))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void connectRejectsIssuerInLinkLocalRange() {
        OAuthAuthorizationFlow flow = newFlow();
        OAuthClientHints hints = new OAuthClientHints(
                URI.create("http://169.254.169.254/"),
                List.of(), "id", null, false, 0, Duration.ofSeconds(2));

        assertThatThrownBy(() -> flow.connect(URI.create("https://x"), hints))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void connectRejectsIssuerInPrivateRange() {
        OAuthAuthorizationFlow flow = newFlow();
        OAuthClientHints hints = new OAuthClientHints(
                URI.create("http://10.0.0.1/"),
                List.of(), "id", null, false, 0, Duration.ofSeconds(2));

        assertThatThrownBy(() -> flow.connect(URI.create("https://x"), hints))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void logsDcrSkippedWhenClientIdAlreadyProvided() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc\",\"token_type\":\"Bearer\",\"expires_in\":300,"
                    + "\"refresh_token\":\"ref\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-pre-registered", null, false, 0,
                Duration.ofSeconds(10));

        flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().contains("DCR skipped"));
    }

    @Test
    void logsErrorWhenCallbackStateMismatches() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallbackWithCorruptState(uri)).start(),
                Clock.systemUTC(),
                eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0,
                Duration.ofSeconds(10));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"), hints))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("state mismatch");

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.ERROR
                        && entry.message().contains("OAuth callback rejected")
                        && entry.message().contains("state mismatch"));
    }

    @Test
    void logsBrowserOpenAndTokenExchangeSuccess() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc\",\"token_type\":\"Bearer\",\"expires_in\":300,"
                    + "\"refresh_token\":\"ref\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0,
                Duration.ofSeconds(10));

        flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        List<McpEventLog.LogEntry> entries = eventLog.snapshot();
        assertThat(entries).anyMatch(entry -> entry.message().contains("OAuth flow starting"));
        assertThat(entries).anyMatch(entry -> entry.message().contains("Opening browser"));
        assertThat(entries).anyMatch(entry -> entry.message().contains("Token exchange succeeded"));
    }

    private static void deliverCallbackWithCorruptState(URI authorizeUri) {
        Map<String, String> params = parseQuery(authorizeUri.getRawQuery());
        String redirectUri = params.get("redirect_uri");
        try {
            awaitCallbackPort(URI.create(redirectUri));
            HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder()
                            .uri(URI.create(redirectUri + "?code=auth-code&state=tampered"))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void resolveMetadataRejectsIssuerMismatch() throws Exception {
        String fetchIssuer = "http://127.0.0.1:" + authPort;
        String declaredIssuer = "https://different-host.example.com";
        String authPath = "/authorize";
        String tokenPath = "/token";

        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            String body = "{"
                    + "\"issuer\":\"" + declaredIssuer + "\","
                    + "\"authorization_endpoint\":\"" + fetchIssuer + authPath + "\","
                    + "\"token_endpoint\":\"" + fetchIssuer + tokenPath + "\","
                    + "\"response_types_supported\":[\"code\"],"
                    + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
                    + "\"code_challenge_methods_supported\":[\"S256\"]"
                    + "}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.createContext(tokenPath, exchange -> {
            String body = "{\"access_token\":\"acc-lenient\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref-lenient\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(fetchIssuer), List.of(), "client-test", null, false, 0,
                Duration.ofSeconds(10));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"), hints))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void resolveMetadataStrictPathEmitsNoRfc8414Warning() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc\",\"token_type\":\"Bearer\",\"expires_in\":300,"
                    + "\"refresh_token\":\"ref\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0,
                Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("acc");
        assertThat(eventLog.snapshot())
                .noneMatch(entry -> entry.message().contains("RFC 8414"));
    }

    @Test
    void resolveMetadataFollowsTwoGatedRedirectHops() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        AtomicInteger finalMetadataGets = new AtomicInteger();
        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            exchange.getResponseHeaders().add("Location", "/metadata-hop-one");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        authServer.createContext("/metadata-hop-one", exchange -> {
            exchange.getResponseHeaders().add("Location", "/metadata-final");
            exchange.sendResponseHeaders(307, -1);
            exchange.close();
        });
        authServer.createContext("/metadata-final", exchange -> {
            finalMetadataGets.incrementAndGet();
            writeResponse(exchange, metadataJson(issuer, "/authorize", "/token"));
        });
        authServer.createContext("/token", exchange -> writeResponse(exchange,
                "{\"access_token\":\"acc\",\"token_type\":\"Bearer\",\"expires_in\":300}"));
        authServer.start();

        List<URI> checkedDestinations = new java.util.concurrent.CopyOnWriteArrayList<>();
        SuspiciousDestinationGate recordingGate = (url, purpose) -> {
            checkedDestinations.add(url);
            return VALIDATOR_GATE.evaluate(url, purpose);
        };
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(), Clock.systemUTC(),
                recordingGate, null);

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"),
                new OAuthClientHints(URI.create(issuer), List.of(), "client-test", null,
                        false, 0, Duration.ofSeconds(10)));

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("acc");
        assertThat(finalMetadataGets).hasValue(1);
        assertThat(checkedDestinations).contains(URI.create(issuer + "/.well-known/oauth-authorization-server"),
                URI.create(issuer + "/metadata-hop-one"), URI.create(issuer + "/metadata-final"));
    }

    @Test
    void resolveMetadataRejectsUnsafeRedirectBeforeRequestingDestination() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            exchange.getResponseHeaders().add("Location", "/blocked-metadata");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        AtomicInteger blockedGets = new AtomicInteger();
        authServer.createContext("/blocked-metadata", exchange -> {
            blockedGets.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        authServer.start();
        SuspiciousDestinationGate rejectingGate = (url, purpose) -> url.getPath().equals("/blocked-metadata")
                ? SuspiciousDestinationGate.Decision.deny(new SuspiciousDestinationGate.Reason(
                        url, null, List.of("test-rejection"), purpose, "blocked"))
                : VALIDATOR_GATE.evaluate(url, purpose);
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(), uri -> { },
                Clock.systemUTC(), rejectingGate, null);

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"),
                new OAuthClientHints(URI.create(issuer), List.of(), "client-test", null,
                        false, 0, Duration.ofSeconds(2))))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("Failed to resolve authorization server metadata");
        assertThat(blockedGets).hasValue(0);
    }

    @Test
    void redirectedMetadataStillMustDeclareTheOriginalIssuer() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String differentIssuer = "https://different-issuer.example";
        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            exchange.getResponseHeaders().add("Location", "/metadata-final");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        authServer.createContext("/metadata-final", exchange ->
                writeResponse(exchange, metadataJson(differentIssuer, "/authorize", "/token")));
        authServer.start();
        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow flow = newFlow(CallbackListenerFactory.defaultFactory(), uri -> { },
                Clock.systemUTC(), eventLog);

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"),
                new OAuthClientHints(URI.create(issuer), List.of(), "client-test", null,
                        false, 0, Duration.ofSeconds(2))))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("issuer mismatch");
        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                .anyMatch(message -> message.contains("declares issuer " + differentIssuer)
                        && message.contains(issuer + " was expected"));
    }

    private static String metadataJson(String issuer, String authorizationPath, String tokenPath) {
        return "{\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + authorizationPath + "\","
                + "\"token_endpoint\":\"" + issuer + tokenPath + "\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
                + "\"code_challenge_methods_supported\":[\"S256\"]}";
    }

    private static void writeResponse(com.sun.net.httpserver.HttpExchange exchange, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }




    @Test
    void resolveMetadataWrapsNonIssuerGeneralExceptionAsOAuthException() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            byte[] bytes = "{not-valid-json".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        OAuthAuthorizationFlow flow = newFlow();
        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0,
                Duration.ofSeconds(10));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"), hints))
                .isInstanceOf(OAuthException.class)
                .hasMessageStartingWith("Failed to resolve authorization server metadata:");
    }

    @Test
    void connectFailsWhenGateDeniesIssuerFetch() {
        SuspiciousDestinationGate denyingGate = (url, purpose) ->
                SuspiciousDestinationGate.Decision.deny(
                        new SuspiciousDestinationGate.Reason(url, "10.0.0.5",
                                List.of("private"), purpose, "denied by user"));

        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> { /* never reached */ },
                Clock.systemUTC(),
                denyingGate,
                null);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create("https://internal.corp/issuer"),
                List.of(), "client-test", null, false, 0, Duration.ofSeconds(2));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"), hints))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("Refusing to fetch")
                .hasMessageContaining("denied by user");
    }

    @Test
    void connectPropagatesMcpEndpointAsCrossOriginContextToGate() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc\",\"token_type\":\"Bearer\",\"expires_in\":300,"
                    + "\"refresh_token\":\"ref\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        RecordingGate recordingGate = new RecordingGate();
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                recordingGate,
                null);

        URI mcp = URI.create("https://mcp.example.com/mcp");
        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0,
                Duration.ofSeconds(10));

        flow.connect(mcp, hints);

        assertThat(recordingGate.invocations)
                .allMatch(inv -> mcp.equals(inv.purpose().mcpEndpoint()));
        assertThat(recordingGate.invocations)
                .extracting(inv -> inv.purpose().label())
                .contains("OAuth issuer metadata", "OAuth authorization endpoint", "OAuth token endpoint");
    }

    private static final class RecordingGate implements SuspiciousDestinationGate {
        private final java.util.List<Invocation> invocations =
                java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        @Override
        public Decision evaluate(URI url, FetchPurpose purpose) {
            invocations.add(new Invocation(url, purpose));
            return Decision.allow();
        }

        private record Invocation(URI url, FetchPurpose purpose) {}
    }

    // ---------------------------------------------------------------------------------------
    // Nimbus-via-Burp routing: every send (strict metadata resolve, DCR, token, refresh, lenient
    // metadata) must travel through the injected Http rather than Nimbus's own transport.
    // ---------------------------------------------------------------------------------------

    private static final com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate ALLOW_ALL =
            (url, purpose) -> com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate.Decision.allow();

    private OAuthAuthorizationFlow flowRoutedThrough(burp.api.montoya.http.Http http,
                                                     McpEventLog eventLog) {
        return flowRoutedThrough(http, eventLog, CallbackListenerFactory.defaultFactory());
    }

    private OAuthAuthorizationFlow flowRoutedThrough(burp.api.montoya.http.Http http, McpEventLog eventLog,
                                                     CallbackListenerFactory listeners) {
        return new OAuthAuthorizationFlow(
                listeners,
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                ALLOW_ALL,
                eventLog,
                http);
    }

    @Test
    void connectRoutesDcrTokenAndStrictMetadataThroughBurpHttp() throws Exception {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        String issuer = "http://127.0.0.1:" + authPort;
        String registrationPath = "/register";
        registerMetadataWithRegistration(issuer, "/authorize", "/token", registrationPath);
        authServer.createContext(registrationPath, exchange -> {
            String body = "{\"client_id\":\"dcr-burp-client\","
                    + "\"redirect_uris\":[\"http://localhost:0/callback\"],"
                    + "\"token_endpoint_auth_method\":\"none\","
                    + "\"grant_types\":[\"authorization_code\",\"refresh_token\"],"
                    + "\"response_types\":[\"code\"]}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc-burp\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref-burp\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        RecordingRealHttp http = new RecordingRealHttp();
        OAuthAuthorizationFlow flow = flowRoutedThrough(http, new McpEventLog(null));

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), null, null, true, 0, Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("acc-burp");
        assertThat(session.clientId()).isEqualTo("dcr-burp-client");
        // The strict metadata GET, the DCR POST, and the token POST must all have gone via Http.
        assertThat(http.sentUrls).anyMatch(u -> u.contains("/.well-known/oauth-authorization-server"));
        assertThat(http.sentMethodsByUrlSuffix("/register")).contains("POST");
        assertThat(http.sentMethodsByUrlSuffix("/token")).contains("POST");
    }

    @Test
    void refreshRoutesTokenRequestThroughBurpHttp() throws Exception {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc-refresh\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":600,\"refresh_token\":\"ref-refresh\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        RecordingRealHttp http = new RecordingRealHttp();
        OAuthAuthorizationFlow flow = flowRoutedThrough(http, new McpEventLog(null));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"),
                new OAuthClientHints(URI.create(issuer), List.of(), "client-test", null, false, 0,
                        Duration.ofSeconds(5)));
        OAuthTokens tokens = session.sharedSession().refresh();

        assertThat(tokens.accessToken().getValue()).isEqualTo("acc-refresh");
        assertThat(http.sentMethodsByUrlSuffix("/token")).containsExactly("POST", "POST");
        assertThat(http.sentUrls).anyMatch(u -> u.contains("/.well-known/oauth-authorization-server"));
    }

    @Test
    void strictResolveViaBurp_matchingIssuer_succeedsWithoutWarning() throws Exception {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        String issuer = "http://127.0.0.1:" + authPort;
        registerMetadata(issuer, "/authorize", "/token");
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc-strict\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref-strict\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        OAuthAuthorizationFlow flow = flowRoutedThrough(new RecordingRealHttp(), eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0, Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("acc-strict");
        assertThat(eventLog.snapshot()).noneMatch(e -> e.message().contains("RFC 8414"));
    }

    @Test
    void strictResolveViaBurpRejectsMismatchedIssuer() throws Exception {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        String fetchIssuer = "http://127.0.0.1:" + authPort;
        String declaredIssuer = "https://different-host.example.com";
        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            String body = "{\"issuer\":\"" + declaredIssuer + "\","
                    + "\"authorization_endpoint\":\"" + fetchIssuer + "/authorize\","
                    + "\"token_endpoint\":\"" + fetchIssuer + "/token\","
                    + "\"response_types_supported\":[\"code\"],"
                    + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
                    + "\"code_challenge_methods_supported\":[\"S256\"]}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"acc-lenient-burp\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref-lenient-burp\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthAuthorizationFlow flow = flowRoutedThrough(http, eventLog);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(fetchIssuer), List.of(), "client-test", null, false, 0, Duration.ofSeconds(10));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"), hints))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("issuer");
        assertThat(http.sentUrls).anyMatch(u -> u.contains("/.well-known/oauth-authorization-server"));
        assertThat(http.sentUrls).noneMatch(u -> u.endsWith("/token"));
    }

    @Test
    void strictResolveViaBurp_transportFailure_throwsOAuthException() {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        String issuer = "http://127.0.0.1:" + authPort;
        // authServer is created but never started → connection refused → response()==null.
        burp.api.montoya.http.Http failingHttp = new RecordingRealHttp() {
            @Override
            public burp.api.montoya.http.message.HttpRequestResponse sendRequest(
                    burp.api.montoya.http.message.requests.HttpRequest request,
                    burp.api.montoya.http.RequestOptions options) {
                sentUrls.add(request.url());
                return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, null);
            }
        };
        OAuthAuthorizationFlow flow = flowRoutedThrough(failingHttp, new McpEventLog(null));

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0, Duration.ofSeconds(10));

        assertThatThrownBy(() -> flow.connect(URI.create("https://mcp.example.com/mcp"), hints))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("Failed to resolve authorization server metadata");
    }

    private void registerMetadataWithScopes(String issuer,
                                             String authPath,
                                             String tokenPath,
                                             List<String> scopesSupported) {
        String scopesJson = scopesSupported.stream()
                .map(s -> "\"" + s + "\"")
                .reduce((a, b) -> a + "," + b)
                .map(s -> "[" + s + "]")
                .orElse("[]");
        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            String body = "{"
                    + "\"issuer\":\"" + issuer + "\","
                    + "\"authorization_endpoint\":\"" + issuer + authPath + "\","
                    + "\"token_endpoint\":\"" + issuer + tokenPath + "\","
                    + "\"response_types_supported\":[\"code\"],"
                    + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
                    + "\"code_challenge_methods_supported\":[\"S256\"],"
                    + "\"scopes_supported\":" + scopesJson
                    + "}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
    }

    private void registerMetadata(String issuer, String authPath, String tokenPath) {
        authServer.createContext("/.well-known/oauth-authorization-server", exchange -> {
            String body = "{"
                    + "\"issuer\":\"" + issuer + "\","
                    + "\"authorization_endpoint\":\"" + issuer + authPath + "\","
                    + "\"token_endpoint\":\"" + issuer + tokenPath + "\","
                    + "\"response_types_supported\":[\"code\"],"
                    + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
                    + "\"code_challenge_methods_supported\":[\"S256\"]"
                    + "}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
    }

    private static void deliverCallback(URI authorizeUri) {
        Map<String, String> params = parseQuery(authorizeUri.getRawQuery());
        String redirectUri = params.get("redirect_uri");
        String state = params.get("state");
        try {
            awaitCallbackPort(URI.create(redirectUri));
            HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder()
                            .uri(URI.create(redirectUri + "?code=auth-code&state="
                                    + URLEncoder.encode(state, StandardCharsets.UTF_8)))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void awaitCallbackPort(URI callbackUri) {
        int port = callbackUri.getPort();
        String host = callbackUri.getHost();
        await().atMost(ofSeconds(5)).until(() -> {
            try (Socket s = new Socket(host, port)) {
                return s.isConnected();
            } catch (IOException e) {
                return false;
            }
        });
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> out = new HashMap<>();
        if (query == null) return out;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                out.put(java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return out;
    }

    private static Map<String, String> parseForm(String form) {
        return parseQuery(form);
    }
}
