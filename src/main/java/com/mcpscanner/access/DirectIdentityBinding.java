package com.mcpscanner.access;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.SessionHandshake;
import com.mcpscanner.checks.shared.session.SessionHeaders;
import com.mcpscanner.mcp.HeaderMutation;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

public final class DirectIdentityBinding implements IdentityBinding {

    private final Http http;
    private final SessionHandshake handshake = new SessionHandshake(this::sendDirect);
    private final Supplier<Optional<String>> liveSession;
    private final Consumer<String> warnings;

    public DirectIdentityBinding(Http http, Supplier<Optional<String>> liveSession, Consumer<String> warnings) {
        this.http = http;
        this.liveSession = liveSession;
        this.warnings = warnings;
    }

    @Override
    public HttpRequest bind(Principal principal, HttpRequest credentialed) {
        Optional<String> session = Principal.PRIMARY_ID.equals(principal.id())
                ? liveSession.get()
                : sessionOpenedFor(principal, credentialed);
        return session.map(id -> SessionHeaders.inSession(credentialed, id)).orElse(credentialed);
    }

    private Optional<String> sessionOpenedFor(Principal principal, HttpRequest sessionless) {
        HttpRequestResponse initialize = handshake.initialize(sessionless);
        Optional<String> refusal = refusalOf(initialize);
        if (refusal.isPresent()) {
            warnings.accept("Could not open an MCP session for " + principal.name() + " (" + refusal.get()
                    + "), so the request sent as " + principal.name() + " has no " + McpHeaders.SESSION_ID);
            return Optional.empty();
        }
        return SessionHeaders.issuedBy(initialize)
                .map(sessionId -> handshake.join(sessionless, sessionId, joined -> { }))
                .flatMap(SessionHeaders::carriedBy);
    }

    private static Optional<String> refusalOf(HttpRequestResponse initialize) {
        if (initialize == null || initialize.response() == null) {
            return Optional.of("no reply to initialize");
        }
        int status = initialize.response().statusCode();
        return status / 100 == 2 ? Optional.empty() : Optional.of("initialize answered HTTP " + status);
    }

    private HttpRequestResponse sendDirect(HttpRequest request) {
        try {
            return http.sendRequest(HeaderMutation.apply(request, List.of(), ScannerSentinels.directDeliveryOnly()));
        } catch (RuntimeException unreachable) {
            return null;
        }
    }
}
