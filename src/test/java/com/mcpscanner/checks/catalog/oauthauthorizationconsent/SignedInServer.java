package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.oauth.ScriptedHttp;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.html;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.json;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.queryParameter;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.redirect;

final class SignedInServer {

    static final String ORIGIN = "https://as.example.com";
    static final String MCP = "https://as.example.com/mcp";
    static final String AUTHORIZE = ORIGIN + "/authorize";
    static final String DECIDE = ORIGIN + "/authorize/decide";
    static final String REGISTER = ORIGIN + "/register";
    static final String TOKEN = ORIGIN + "/token";
    static final String REVOKE = ORIGIN + "/revoke";
    static final String SESSION_COOKIE = "alice-session-secret";
    static final String TRANSACTION_COOKIE = "transaction-secret";
    static final String SCANNER_ID = "scanner-client";
    static final String SCANNER_NAME = "Burp MCP Scanner";
    static final URI SCANNER_REDIRECT = URI.create("http://127.0.0.1:8765/callback");
    static final Set<String> GRANTED = Set.of("read");

    record Client(String id, String name, URI redirect, Optional<String> softwareId) {
    }

    private final ScriptedHttp http = new ScriptedHttp();
    private final Map<String, Client> clients = new ConcurrentHashMap<>();
    private final Map<String, String> codes = new ConcurrentHashMap<>();
    private final Map<String, String> codeScopes = new ConcurrentHashMap<>();
    private Function<String, Optional<String>> tokenScope = Optional::of;
    private Optional<String> scannerSecret = Optional.empty();
    private final AtomicInteger issued = new AtomicInteger();
    private BiPredicate<Client, Set<String>> remembered = SignedInServer::rememberedPerClientAndScope;
    private Function<Client, String> clientIds = client -> UUID.randomUUID().toString();
    private String scopesSupported = "[\"read\",\"write\",\"admin\"]";
    private String authorizationEndpoint = AUTHORIZE;
    private String registrationEndpoint = REGISTER;
    private String tokenEndpoint = TOKEN;
    private BiFunction<Client, HttpRequest, String> consentPrompt =
            (client, request) -> html("<form><button>Allow " + client.name() + "</button></form>");

    SignedInServer() {
        clients.put(SCANNER_ID, new Client(SCANNER_ID, SCANNER_NAME, SCANNER_REDIRECT, Optional.of("burp-mcp")));
        http.on("GET", ORIGIN + "/.well-known/oauth-authorization-server", request -> json(200,
                        "{\"issuer\":\"" + ORIGIN + "\",\"authorization_endpoint\":\"" + authorizationEndpoint + "\","
                                + "\"registration_endpoint\":\"" + registrationEndpoint + "\","
                                + "\"token_endpoint\":\"" + tokenEndpoint + "\",\"revocation_endpoint\":\"" + REVOKE + "\",\"scopes_supported\":"
                                + scopesSupported + "}"))
                .on("POST", REGISTER, this::register)
                .on("GET", AUTHORIZE, this::authorize)
                .on("GET", DECIDE, this::decide)
                .on("POST", TOKEN, this::redeem)
                .on("POST", MCP, this::answerMcp)
                .on("POST", REVOKE, ScriptedHttp.status(200));
    }

    static boolean rememberedPerClientAndScope(Client client, Set<String> scopes) {
        return client.id().equals(SCANNER_ID) && GRANTED.containsAll(scopes);
    }

    ScriptedHttp http() {
        return http;
    }

    SignedInServer rememberWhen(BiPredicate<Client, Set<String>> rule) {
        remembered = rule;
        return this;
    }

    SignedInServer promptWith(BiFunction<Client, HttpRequest, String> prompt) {
        consentPrompt = prompt;
        return this;
    }

    SignedInServer scannerClientIsConfidentialWith(String secret) {
        scannerSecret = Optional.of(secret);
        return this;
    }

    SignedInServer answerTokenScope(Function<String, Optional<String>> granted) {
        tokenScope = granted;
        return this;
    }

    List<HttpRequest> redemptionsBy(String clientId) {
        return http.sentTo(TOKEN).stream().filter(request -> request.bodyToString().contains("client_id=" + clientId))
                .toList();
    }

    SignedInServer mintClientIds(Function<Client, String> minting) {
        clientIds = minting;
        return this;
    }

    SignedInServer advertiseScopes(String jsonArray) {
        scopesSupported = jsonArray;
        return this;
    }

    SignedInServer protectResourceWithScopes(String jsonArray) {
        http.on("GET", ORIGIN + "/.well-known/oauth-protected-resource/mcp", json(200,
                "{\"resource\":\"" + MCP + "\",\"authorization_servers\":[\"" + ORIGIN + "\"],"
                        + "\"scopes_supported\":" + jsonArray + "}"));
        return this;
    }

    List<String> requestedScopes(String clientId) {
        return http.sentTo(AUTHORIZE).stream().filter(request -> clientId.equals(queryParameter(request, "client_id")))
                .map(request -> String.valueOf(queryParameter(request, "scope")))
                .toList();
    }

    SignedInServer advertiseAuthorizationEndpoint(String endpoint) {
        authorizationEndpoint = endpoint;
        return this;
    }

    SignedInServer advertiseRegistrationAndTokenAt(String origin) {
        registrationEndpoint = origin + "/register";
        tokenEndpoint = origin + "/token";
        return this;
    }

    SignedInServer protectResourceNamed(String resource) {
        http.on("GET", ORIGIN + "/.well-known/oauth-protected-resource/mcp", json(200,
                "{\"resource\":\"" + resource + "\",\"authorization_servers\":[\"" + ORIGIN + "\"]}"));
        return this;
    }

    SignedInServer delegateToIssuer(String issuer) {
        http.on("GET", ORIGIN + "/.well-known/oauth-protected-resource/mcp", json(200,
                        "{\"resource\":\"" + MCP + "\",\"authorization_servers\":[\"" + issuer + "\"]}"))
                .on("GET", issuer + "/.well-known/oauth-authorization-server", json(200,
                        "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\"" + issuer + "/authorize\","
                                + "\"registration_endpoint\":\"" + issuer + "/register\",\"token_endpoint\":\""
                                + issuer + "/token\"}"));
        return this;
    }

    SignedInServer withoutRegistration() {
        http.on("GET", ORIGIN + "/.well-known/oauth-authorization-server", json(200,
                "{\"issuer\":\"" + ORIGIN + "\",\"authorization_endpoint\":\"" + AUTHORIZE + "\"}"));
        return this;
    }

    List<HttpRequest> registrations() {
        return http.sentTo(REGISTER);
    }

    List<String> deletedClients() {
        return http.sent().stream().filter(request -> request.method().equals("DELETE"))
                .map(request -> request.url().substring((REGISTER + "/").length()))
                .toList();
    }

    List<String> revokedTokens() {
        return http.sentTo(REVOKE).stream().map(request -> form(request.bodyToString()).get("token")).toList();
    }

    List<String> registeredIds() {
        return clients.keySet().stream().filter(id -> !id.equals(SCANNER_ID)).toList();
    }

    private String register(HttpRequest request) {
        String body = request.bodyToString();
        Client unnamed = new Client("", field(body, "client_name"),
                URI.create(body.replaceAll(".*\"redirect_uris\":\\[\"([^\"]*)\".*", "$1")),
                Optional.ofNullable(body.contains("software_id") ? field(body, "software_id") : null));
        Client client = new Client(clientIds.apply(unnamed), unnamed.name(), unnamed.redirect(), unnamed.softwareId());
        clients.put(client.id(), client);
        http.on("DELETE", REGISTER + "/" + client.id(), ScriptedHttp.status(204));
        return json(201, "{\"client_id\":\"" + client.id() + "\",\"redirect_uris\":[\"" + client.redirect()
                + "\"],\"registration_client_uri\":\"" + REGISTER + "/" + client.id()
                + "\",\"registration_access_token\":\"rat\"}");
    }

    private String authorize(HttpRequest request) {
        if (!String.valueOf(request.headerValue("Cookie")).contains("sid=" + SESSION_COOKIE)) {
            return html("<form action=/login><input name=password></form>");
        }
        return "HTTP/1.1 302 Found\r\nSet-Cookie: tx=" + TRANSACTION_COOKIE + "; Path=/; HttpOnly\r\nLocation: "
                + DECIDE + "?" + URI.create(request.url()).getRawQuery() + "\r\n\r\n";
    }

    private String decide(HttpRequest request) {
        String cookies = String.valueOf(request.headerValue("Cookie"));
        Client client = clients.get(queryParameter(request, "client_id"));
        if (!cookies.contains("sid=" + SESSION_COOKIE) || !cookies.contains("tx=" + TRANSACTION_COOKIE)
                || client == null || !client.redirect().toString().equals(queryParameter(request, "redirect_uri"))) {
            return html(400, "<p>invalid request</p>");
        }
        if (!remembered.test(client, scopes(queryParameter(request, "scope")))) {
            return consentPrompt.apply(client, request);
        }
        String code = "code-" + issued.incrementAndGet();
        codes.put(code, client.id());
        Optional.ofNullable(queryParameter(request, "scope")).ifPresent(scope -> codeScopes.put(code, scope));
        return redirect(client.redirect() + "?code=" + code + "&state=" + queryParameter(request, "state"));
    }

    private String redeem(HttpRequest request) {
        Map<String, String> form = form(request.bodyToString());
        String clientId = form.containsKey("client_id") ? form.get("client_id") : basicClientId(request);
        if (SCANNER_ID.equals(clientId) && scannerSecret.isPresent() && !scannerSecret.map(secret -> "Basic "
                + Base64.getEncoder().encodeToString((SCANNER_ID + ":" + secret).getBytes(StandardCharsets.UTF_8)))
                .get().equals(request.headerValue("Authorization"))) {
            return json(401, "{\"error\":\"invalid_client\"}");
        }
        String owner = codes.remove(form.getOrDefault("code", ""));
        if (owner == null || !owner.equals(clientId)) {
            return json(400, "{\"error\":\"invalid_grant\"}");
        }
        String scope = Optional.ofNullable(codeScopes.get(form.get("code"))).flatMap(tokenScope)
                .map(granted -> ",\"scope\":\"" + granted + "\"").orElse("");
        return json(200, "{\"access_token\":\"token-" + form.get("code") + "\",\"token_type\":\"Bearer\"" + scope
                + "}");
    }

    private static String basicClientId(HttpRequest request) {
        String authorization = String.valueOf(request.headerValue("Authorization"));
        if (!authorization.startsWith("Basic ")) {
            return null;
        }
        String decoded = new String(Base64.getDecoder().decode(authorization.substring("Basic ".length())),
                StandardCharsets.UTF_8);
        return decode(decoded.split(":", 2)[0]);
    }

    private String answerMcp(HttpRequest request) {
        String authorization = request.headerValue("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer token-code-")) {
            return "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\nContent-Type: application/json\r\n\r\n"
                    + "{\"error\":\"invalid_token\"}";
        }
        String id = request.bodyToString().replaceAll("(?s).*\"id\"\\s*:\\s*(\\d+).*", "$1");
        return json(200, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"tools\":[]}}");
    }

    private static Set<String> scopes(String scope) {
        return scope == null ? Set.of() : Set.of(scope.split(" "));
    }

    private static String field(String body, String name) {
        return body.replaceAll(".*\"" + name + "\":\"([^\"]*)\".*", "$1");
    }

    private static Map<String, String> form(String body) {
        return Arrays.stream(body.split("&"))
                .map(pair -> pair.split("=", 2))
                .filter(pair -> pair.length == 2)
                .collect(Collectors.toMap(pair -> decode(pair[0]), pair -> decode(pair[1]), (first, second) -> first));
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
