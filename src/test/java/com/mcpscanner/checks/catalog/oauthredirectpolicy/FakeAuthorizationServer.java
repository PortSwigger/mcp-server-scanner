package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.checks.shared.oauth.RegisteredClient;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class FakeAuthorizationServer {

    static final URI ISSUER = URI.create("https://auth.example.com");
    static final URI AUTHORIZATION_ENDPOINT = URI.create("https://auth.example.com/authorize");
    static final URI REGISTRATION_ENDPOINT = URI.create("https://auth.example.com/register");
    static final URI RESOURCE = URI.create("https://mcp.example.com/mcp");

    enum RegistrationReply { ECHO, OMIT_REDIRECT_URIS, REWRITE_REDIRECT_URIS, REJECT, UNAUTHORIZED, FAIL }

    enum AuthorizationReply { DELIVER, DELIVER_NORMALISED, DELIVER_ERROR, REJECT, FAIL }

    interface RegistrationPolicy {
        RegistrationReply reply(List<String> redirectUris);
    }

    interface RedirectPolicy {
        AuthorizationReply reply(String redirectUri, List<String> clientRedirectUris);
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ScriptedHttp http;
    private final Map<String, List<String>> clients = new LinkedHashMap<>();
    private RegistrationPolicy registrationPolicy = redirectUris -> RegistrationReply.ECHO;
    private RedirectPolicy redirectPolicy = exactMatch();
    private boolean managesClients;
    private boolean issuesClientSecrets;
    private boolean issuesUnmanagedRegistrationTokens;
    private boolean throttlesAuthorization;

    FakeAuthorizationServer() {
        this(new ScriptedHttp());
    }

    FakeAuthorizationServer(ScriptedHttp http) {
        this.http = http;
        http.on("POST", REGISTRATION_ENDPOINT, this::register);
        http.on("GET", AUTHORIZATION_ENDPOINT, request -> authorize(QueryParameters.of(request.url())));
        http.on("POST", AUTHORIZATION_ENDPOINT,
                request -> authorize(QueryParameters.ofEncoded(request.bodyToString())));
    }

    static RedirectPolicy exactMatch() {
        return (redirectUri, registered) -> registered.contains(redirectUri)
                ? AuthorizationReply.DELIVER : AuthorizationReply.REJECT;
    }

    static RedirectPolicy anyRedirect() {
        return (redirectUri, registered) -> AuthorizationReply.DELIVER;
    }

    FakeAuthorizationServer registering(RegistrationPolicy policy) {
        this.registrationPolicy = policy;
        return this;
    }

    FakeAuthorizationServer redirecting(RedirectPolicy policy) {
        this.redirectPolicy = policy;
        return this;
    }

    FakeAuthorizationServer managingClients() {
        this.managesClients = true;
        return this;
    }

    FakeAuthorizationServer withClientSecrets() {
        this.issuesClientSecrets = true;
        return this;
    }

    FakeAuthorizationServer issuingUnmanagedRegistrationTokens() {
        this.issuesUnmanagedRegistrationTokens = true;
        return this;
    }

    FakeAuthorizationServer throttlingAuthorization() {
        this.throttlesAuthorization = true;
        return this;
    }

    ScriptedHttp http() {
        return http;
    }

    List<HttpRequest> registrations() {
        return http.sent("POST", REGISTRATION_ENDPOINT);
    }

    List<HttpRequest> deletions() {
        return http.sent().stream().filter(request -> "DELETE".equals(request.method())).toList();
    }

    List<HttpRequest> authorizations() {
        List<HttpRequest> authorizations = new ArrayList<>(http.sent("GET", AUTHORIZATION_ENDPOINT));
        authorizations.addAll(http.sent("POST", AUTHORIZATION_ENDPOINT));
        return authorizations;
    }

    static List<String> registeredRedirectUris(HttpRequest registration) {
        List<String> uris = new ArrayList<>();
        readTree(registration.bodyToString()).path("redirect_uris").forEach(uri -> uris.add(uri.asText()));
        return uris;
    }

    AuthorizationServer server() {
        return new AuthorizationServer(ISSUER, AUTHORIZATION_ENDPOINT, Optional.of(REGISTRATION_ENDPOINT), Optional.empty(),
                Optional.empty(), RESOURCE,
                Optional.empty(), List.of());
    }

    ProbeClientRegistrar registrar() {
        return new ProbeClientRegistrar(http.oauth(), REGISTRATION_ENDPOINT);
    }

    OwnedClient ownedClient(URI callback) {
        RegisteredClient client = registrar().register(ProbeClientMetadata.redirectingTo(List.of(callback.toString())))
                .client().orElseThrow();
        return new OwnedClient(client, callback);
    }

    DeliveryProbe deliveryProbe() {
        Authorizer authorizer = new Authorizer(http.oauth(), new AuthorizationRequestFactory(server()), Map.of());
        return new DeliveryProbe(authorizer, AUTHORIZATION_ENDPOINT);
    }

    ProbeContext probeContext() {
        ProbeClientRegistrar registrar = registrar();
        return new ProbeContext(registrar, new OwnedClients(registrar), deliveryProbe());
    }

    private String register(HttpRequest request) {
        List<String> redirectUris = registeredRedirectUris(request);
        return switch (registrationPolicy.reply(redirectUris)) {
            case ECHO -> registered(redirectUris, redirectUris);
            case OMIT_REDIRECT_URIS -> registered(redirectUris, List.of());
            case REWRITE_REDIRECT_URIS -> registered(redirectUris, List.of(ISSUER + "/callback"));
            case REJECT -> RawResponses.json(400, "{\"error\":\"invalid_redirect_uri\"}");
            case UNAUTHORIZED -> RawResponses.json(401, "{\"error\":\"invalid_token\"}");
            case FAIL -> RawResponses.status(500);
        };
    }

    private String registered(List<String> redirectUris, List<String> echoed) {
        String clientId = "client-" + (clients.size() + 1);
        clients.put(clientId, redirectUris);
        ObjectNode body = JSON.createObjectNode().put("client_id", clientId);
        ArrayNode uris = body.putArray("redirect_uris");
        echoed.forEach(uris::add);
        if (issuesUnmanagedRegistrationTokens) {
            body.put("registration_client_uri", "http://internal-as:8080/register/" + clientId)
                    .put("registration_access_token", "rat-" + clientId);
        }
        if (issuesClientSecrets) {
            body.put("client_secret", "secret-" + clientId);
        }
        if (managesClients) {
            URI management = URI.create(REGISTRATION_ENDPOINT + "/" + clientId);
            body.put("registration_client_uri", management.toString()).put("registration_access_token", "rat-" + clientId);
            http.on("DELETE", management, request -> RawResponses.status(204));
        }
        return RawResponses.json(201, body.toString());
    }

    private String authorize(Map<String, String> parameters) {
        List<String> registered = clients.get(parameters.get("client_id"));
        if (throttlesAuthorization) {
            return RawResponses.status(429);
        }
        if (registered == null) {
            return RawResponses.status(400);
        }
        String redirectUri = parameters.get("redirect_uri");
        return switch (redirectPolicy.reply(redirectUri, registered)) {
            case DELIVER -> deliver(redirectUri, parameters, grantFor(parameters));
            case DELIVER_NORMALISED -> deliver(URI.create(redirectUri).normalize().toString(), parameters,
                    grantFor(parameters));
            case DELIVER_ERROR -> deliver(redirectUri, parameters, "error=access_denied");
            case REJECT -> RawResponses.status(400);
            case FAIL -> RawResponses.status(500);
        };
    }

    private static String grantFor(Map<String, String> parameters) {
        if ("false".equals(parameters.get("allow"))) {
            return "error=access_denied";
        }
        return "code".equals(parameters.get("response_type")) ? "code=scripted-code" : "error=unsupported_response_type";
    }

    private static String deliver(String redirectUri, Map<String, String> parameters, String result) {
        String response = result + "&state=" + URLEncoder.encode(parameters.get("state"), StandardCharsets.UTF_8);
        String separator = "fragment".equals(parameters.get("response_mode")) ? "#"
                : redirectUri.contains("?") ? "&" : "?";
        return RawResponses.redirect(redirectUri + separator + response);
    }

    private static JsonNode readTree(String body) {
        try {
            return JSON.readTree(body);
        } catch (Exception malformed) {
            throw new IllegalStateException(malformed);
        }
    }
}
