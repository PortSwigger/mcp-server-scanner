package com.mcpscanner.auth.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.auth.oauth.safety.FetchPurpose;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.RecordingRealHttp;
import com.mcpscanner.mcp.McpObjectMapper;
import com.sun.net.httpserver.HttpServer;
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

class OAuthAuthorizationFlowTest {

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
        try {
            new OAuthUrlValidator().validate(url);
            return SuspiciousDestinationGate.Decision.allow();
        } catch (OAuthException rejection) {
            return SuspiciousDestinationGate.Decision.deny(new SuspiciousDestinationGate.Reason(
                    url, null, List.of("validator-rejected"), purpose, rejection.getMessage()));
        }
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
                                           McpEventLog eventLog,
                                           OAuthMetadataConsistencyListener anomalyListener) {
        return new OAuthAuthorizationFlow(listenerFactory, browserLauncher, clock, gate,
                eventLog, anomalyListener, new RecordingRealHttp());
    }

    private OAuthAuthorizationFlow newFlow(CallbackListenerFactory listenerFactory,
                                           BrowserLauncher browserLauncher,
                                           Clock clock) {
        return newFlow(listenerFactory, browserLauncher, clock, VALIDATOR_GATE, McpEventLog.noop(),
                OAuthMetadataConsistencyListener.noop());
    }

    private OAuthAuthorizationFlow newFlow(CallbackListenerFactory listenerFactory,
                                           BrowserLauncher browserLauncher,
                                           Clock clock,
                                           McpEventLog eventLog) {
        return newFlow(listenerFactory, browserLauncher, clock, VALIDATOR_GATE, eventLog,
                OAuthMetadataConsistencyListener.noop());
    }

    private OAuthAuthorizationFlow newFlow(CallbackListenerFactory listenerFactory,
                                           BrowserLauncher browserLauncher,
                                           Clock clock,
                                           McpEventLog eventLog,
                                           OAuthMetadataConsistencyListener anomalyListener) {
        return newFlow(listenerFactory, browserLauncher, clock, VALIDATOR_GATE, eventLog, anomalyListener);
    }

    /** No-arg-equivalent flow: default factory + desktop launcher, validator gate, routed via Burp. */
    private OAuthAuthorizationFlow newFlow() {
        return newFlow(CallbackListenerFactory.defaultFactory(),
                BrowserLauncher.desktopLauncher(McpEventLog.noop()), Clock.systemUTC());
    }

    @AfterEach
    void stopAuthServer() {
        if (authServer != null) {
            authServer.stop(0);
        }
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
                .hasMessageContaining("HTTP 400")
                .hasMessageContaining("(empty response body)");

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("DCR registration failed: HTTP 400 (empty response body)"));
    }

    @Test
    void dcrErrorMessageIncludesCodeAndDescriptionWhenProvided() throws Exception {
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
                        && entry.message().contains("HTTP 400")
                        && entry.message().contains("invalid_client_metadata")
                        && entry.message().contains("redirect_uri not registered"));
    }

    @Test
    void dcrErrorMessageHandlesNullThrowableMessage() throws Exception {
        // Simulate an IOException with a null getMessage() reaching the registerClient
        // catch block. Closing the TCP socket mid-handshake yields a SocketException
        // whose message is JDK-dependent (sometimes null, sometimes "Connection reset"),
        // so we exercise the fallback helper directly via reflection — that is the only
        // way to deterministically prove the null branch picks up the class name.
        OAuthAuthorizationFlow flow = newFlow();
        java.lang.reflect.Method messageOf =
                OAuthAuthorizationFlow.class.getDeclaredMethod("messageOf", Throwable.class);
        messageOf.setAccessible(true);

        String fromNullMessage = (String) messageOf.invoke(flow, new IOException((String) null));
        assertThat(fromNullMessage).isEqualTo("IOException");

        String fromEmptyMessage = (String) messageOf.invoke(flow, new IOException(""));
        assertThat(fromEmptyMessage).isEqualTo("IOException");

        String fromRealMessage = (String) messageOf.invoke(flow, new IOException("boom"));
        assertThat(fromRealMessage).isEqualTo("boom");

        // And confirm via the end-to-end DCR path that the WARN line never logs ": null"
        // even when Nimbus surfaces a low-detail wrapped exception.
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

        CallbackListenerFactory portCapturingFactory = (port, path) -> {
            CallbackListener listener = CallbackListener.start(port, path);
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
    void refreshExchangesRefreshTokenForNewTokens() throws Exception {
        String issuer = "http://127.0.0.1:" + authPort;
        String tokenPath = "/token";
        Map<String, String> capturedTokenForm = new HashMap<>();
        registerMetadata(issuer, "/authorize", tokenPath);
        authServer.createContext(tokenPath, exchange -> {
            String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            capturedTokenForm.putAll(parseForm(form));
            String body = "{\"access_token\":\"acc-2\",\"token_type\":\"Bearer\",\"expires_in\":600,"
                    + "\"refresh_token\":\"ref-2\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        OAuthAuthorizationFlow flow = newFlow();

        OAuthTokens tokens = flow.refresh(
                URI.create(issuer),
                "client-test",
                null,
                new com.nimbusds.oauth2.sdk.token.RefreshToken("old-refresh"),
                null);

        assertThat(tokens.accessToken().getValue()).isEqualTo("acc-2");
        assertThat(tokens.refreshToken().getValue()).isEqualTo("ref-2");
        assertThat(capturedTokenForm).containsEntry("grant_type", "refresh_token");
        assertThat(capturedTokenForm).containsEntry("refresh_token", "old-refresh");
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

        OAuthAuthorizationFlow flow = newFlow();

        flow.refresh(
                URI.create(issuer),
                "client-test",
                null,
                new com.nimbusds.oauth2.sdk.token.RefreshToken("old-refresh"),
                mcpResource);

        assertThat(capturedTokenForm).containsEntry("resource", mcpResource.toString());
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
    void refreshRejectsIssuerInPrivateRange() {
        OAuthAuthorizationFlow flow = newFlow();

        assertThatThrownBy(() -> flow.refresh(
                URI.create("http://10.0.0.1/"),
                "client",
                null,
                new com.nimbusds.oauth2.sdk.token.RefreshToken("rt"),
                null))
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
    void resolveMetadataFallsBackLenientlyWhenIssuerMismatches() throws Exception {
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
        RecordingAnomalyListener listener = new RecordingAnomalyListener();
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog,
                listener);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(fetchIssuer), List.of(), "client-test", null, false, 0,
                Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("acc-lenient");
        List<McpEventLog.LogEntry> entries = eventLog.snapshot();
        assertThat(entries)
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().startsWith("AS metadata RFC 8414 §3.3 violation")
                        && entry.message().contains(fetchIssuer)
                        && entry.message().contains(declaredIssuer));

        assertThat(listener.invocations).hasSize(1);
        RecordingAnomalyListener.Invocation only = listener.invocations.get(0);
        assertThat(only.metadataUrl.toString())
                .isEqualTo(fetchIssuer + "/.well-known/oauth-authorization-server");
        assertThat(only.expectedIssuer).isEqualTo(fetchIssuer);
        assertThat(only.returnedIssuer).isEqualTo(declaredIssuer);
        assertThat(only.rawResponseBody).isNotEmpty();
        assertThat(new String(only.rawResponseBody, StandardCharsets.UTF_8))
                .contains("\"issuer\":\"" + declaredIssuer + "\"");
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
    void resolveMetadataDoesNotInvokeListenerOnCompliantMetadata() throws Exception {
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
        RecordingAnomalyListener listener = new RecordingAnomalyListener();
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog,
                listener);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0,
                Duration.ofSeconds(10));

        flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(listener.invocations).isEmpty();
    }

    @Test
    void resolveMetadataSwallowsListenerExceptions() throws Exception {
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
            String body = "{\"access_token\":\"acc-survive\",\"token_type\":\"Bearer\","
                    + "\"expires_in\":300,\"refresh_token\":\"ref-survive\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        authServer.start();

        McpEventLog eventLog = new McpEventLog(null);
        com.mcpscanner.auth.oauth.OAuthProtocolAnomalyListener throwingListener =
                (metadataUrl, expectedIssuer, returnedIssuer, rawResponseBody) -> {
                    throw new IllegalStateException("listener boom");
                };
        OAuthAuthorizationFlow flow = newFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                eventLog,
                throwingListener);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(fetchIssuer), List.of(), "client-test", null, false, 0,
                Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("acc-survive");
        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("OAuthMetadataConsistencyListener.onIssuerMismatch threw")
                        && entry.message().contains("IllegalStateException")
                        && entry.message().contains("listener boom"));
    }

    private static final class RecordingAnomalyListener
            implements com.mcpscanner.auth.oauth.OAuthProtocolAnomalyListener {
        private final java.util.List<Invocation> invocations =
                java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        @Override
        public void onIssuerMismatch(URI metadataUrl,
                                     String expectedIssuer,
                                     String returnedIssuer,
                                     byte[] rawResponseBody) {
            invocations.add(new Invocation(metadataUrl, expectedIssuer, returnedIssuer,
                    rawResponseBody != null ? rawResponseBody.clone() : new byte[0]));
        }

        private static final class Invocation {
            final URI metadataUrl;
            final String expectedIssuer;
            final String returnedIssuer;
            final byte[] rawResponseBody;

            Invocation(URI metadataUrl, String expectedIssuer, String returnedIssuer, byte[] rawResponseBody) {
                this.metadataUrl = metadataUrl;
                this.expectedIssuer = expectedIssuer;
                this.returnedIssuer = returnedIssuer;
                this.rawResponseBody = rawResponseBody;
            }
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
                null,
                OAuthProtocolAnomalyListener.noop());

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
                null,
                OAuthProtocolAnomalyListener.noop());

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

    @Test
    void applyTimeoutsConfiguresConnectAndReadTimeouts() throws Exception {
        OAuthAuthorizationFlow flow = newFlow();
        com.nimbusds.oauth2.sdk.http.HTTPRequest httpRequest =
                new com.nimbusds.oauth2.sdk.http.HTTPRequest(
                        com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.GET,
                        new java.net.URL("https://example.com/"));

        com.nimbusds.oauth2.sdk.http.HTTPRequest configured = flow.applyTimeouts(httpRequest);

        assertThat(configured.getConnectTimeout()).isGreaterThan(0);
        assertThat(configured.getReadTimeout()).isGreaterThan(0);
    }

    // ---------------------------------------------------------------------------------------
    // Nimbus-via-Burp routing: every send (strict metadata resolve, DCR, token, refresh, lenient
    // metadata) must travel through the injected Http rather than Nimbus's own transport.
    // ---------------------------------------------------------------------------------------

    private static final com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate ALLOW_ALL =
            (url, purpose) -> com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate.Decision.allow();

    private OAuthAuthorizationFlow flowRoutedThrough(burp.api.montoya.http.Http http,
                                                     McpEventLog eventLog,
                                                     OAuthMetadataConsistencyListener listener) {
        return new OAuthAuthorizationFlow(
                CallbackListenerFactory.defaultFactory(),
                uri -> new Thread(() -> deliverCallback(uri)).start(),
                Clock.systemUTC(),
                ALLOW_ALL,
                eventLog,
                listener,
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
        OAuthAuthorizationFlow flow = flowRoutedThrough(http, new McpEventLog(null),
                OAuthMetadataConsistencyListener.noop());

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
        OAuthAuthorizationFlow flow = flowRoutedThrough(http, new McpEventLog(null),
                OAuthMetadataConsistencyListener.noop());

        OAuthTokens tokens = flow.refresh(URI.create(issuer), "client-test", null,
                new com.nimbusds.oauth2.sdk.token.RefreshToken("old-refresh"),
                URI.create("https://mcp.example.com/mcp"));

        assertThat(tokens.accessToken().getValue()).isEqualTo("acc-refresh");
        assertThat(http.sentMethodsByUrlSuffix("/token")).contains("POST");
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
        RecordingAnomalyListener listener = new RecordingAnomalyListener();
        OAuthAuthorizationFlow flow = flowRoutedThrough(new RecordingRealHttp(), eventLog, listener);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(issuer), List.of(), "client-test", null, false, 0, Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("acc-strict");
        assertThat(eventLog.snapshot()).noneMatch(e -> e.message().contains("RFC 8414"));
        assertThat(listener.invocations).isEmpty();
    }

    @Test
    void strictResolveViaBurp_mismatchedIssuer_fallsBackToLenientAndNotifies() throws Exception {
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
        RecordingAnomalyListener listener = new RecordingAnomalyListener();
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthAuthorizationFlow flow = flowRoutedThrough(http, eventLog, listener);

        OAuthClientHints hints = new OAuthClientHints(
                URI.create(fetchIssuer), List.of(), "client-test", null, false, 0, Duration.ofSeconds(10));

        OAuthSession session = flow.connect(URI.create("https://mcp.example.com/mcp"), hints);

        assertThat(session.tokens().accessToken().getValue()).isEqualTo("acc-lenient-burp");
        assertThat(eventLog.snapshot())
                .anyMatch(e -> e.level() == McpEventLog.Level.WARN
                        && e.message().startsWith("AS metadata RFC 8414 §3.3 violation")
                        && e.message().contains(fetchIssuer)
                        && e.message().contains(declaredIssuer));
        assertThat(listener.invocations).hasSize(1);
        RecordingAnomalyListener.Invocation only = listener.invocations.get(0);
        assertThat(only.expectedIssuer).isEqualTo(fetchIssuer);
        assertThat(only.returnedIssuer).isEqualTo(declaredIssuer);
        // The lenient re-fetch also routed via Burp.
        assertThat(http.sentUrls).anyMatch(u -> u.contains("/.well-known/oauth-authorization-server"));
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
        OAuthAuthorizationFlow flow = flowRoutedThrough(failingHttp, new McpEventLog(null),
                OAuthMetadataConsistencyListener.noop());

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
