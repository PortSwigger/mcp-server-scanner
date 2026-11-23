package com.mcpscanner.checks.shared.probe;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcMessages;
import com.mcpscanner.checks.shared.session.McpSessionHandshake;
import com.mcpscanner.checks.shared.session.SessionHeaders;
import com.mcpscanner.mcp.McpHeaders;

import java.util.Optional;
import java.util.function.Predicate;

public final class IndependentSessionSender {

    static final String INITIALIZE_ID = "anonymous-probe-initialize";
    static final int MISSING_SESSION_STATUS = 400;

    private final ProbeChannel channel;
    private final BaselineEquivalenceOracle oracle;
    private final McpSessionHandshake handshake = McpSessionHandshake.named(INITIALIZE_ID);

    public IndependentSessionSender(ProbeChannel channel, BaselineEquivalenceOracle oracle) {
        this.channel = channel;
        this.oracle = oracle;
    }

    public ProbeExchange send(HttpRequest probe) {
        return send(probe, this::rejectedForMissingSession);
    }

    public ProbeExchange sendConfirmingRefusalInAFreshSession(HttpRequest probe) {
        return send(probe, exchange -> rejectedForMissingSession(exchange)
                || (oracle.refused(exchange) || ServerErrorAnswer.of(exchange))
                && SessionHeaders.carriedBy(exchange.request()).isEmpty());
    }

    static boolean opensFreshSession(HttpRequest request) {
        return request != null && JsonRpcMessages.parsed(request.bodyToString())
                .map(message -> INITIALIZE_ID.equals(message.path("id").asText(null)))
                .orElse(false);
    }

    private ProbeExchange send(HttpRequest probe, Predicate<HttpRequestResponse> needsFreshSession) {
        HttpRequestResponse first = channel.send(probe);
        if (!needsFreshSession.test(first)) {
            return ProbeExchange.of(first);
        }
        HttpRequestResponse initialize = channel.send(handshake.initialize(probe));
        Optional<String> sessionId = SessionHeaders.issuedBy(initialize);
        if (sessionId.isEmpty()) {
            return oracle.refused(initialize) ? ProbeExchange.of(first, initialize) : ProbeExchange.interrupted(first);
        }
        channel.send(handshake.initialized(probe, sessionId.get()));
        HttpRequestResponse retried = channel.send(probe.withHeader(McpHeaders.SESSION_ID, sessionId.get()));
        return ProbeExchange.of(first, initialize, retried);
    }

    private boolean rejectedForMissingSession(HttpRequestResponse exchange) {
        return exchange != null && exchange.response() != null
                && exchange.response().statusCode() == MISSING_SESSION_STATUS
                && SessionHeaders.carriedBy(exchange.request()).isEmpty()
                && !oracle.refused(exchange);
    }
}
