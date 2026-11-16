package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.crossidentity.OpenedSessions;
import com.mcpscanner.checks.api.crossidentity.SessionAdmission;
import com.mcpscanner.checks.api.crossidentity.SessionHandshake;
import com.mcpscanner.checks.shared.session.SessionHeaders;
import com.mcpscanner.mcp.McpHeaders;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

final class RunSessions {

    private final ComparisonTransport transport;
    private final SessionHandshake handshake;
    private final OpenedSessions opened = new OpenedSessions();
    private final Map<String, Slot> slots = new ConcurrentHashMap<>();

    RunSessions(ComparisonTransport transport) {
        this.transport = transport;
        this.handshake = new SessionHandshake(transport::send);
    }

    SessionAdmission admit(String routingId, HttpRequest request, boolean stateful) {
        if (!stateful) {
            return SessionAdmission.admitted(request);
        }
        HttpRequest sessionless = request.withRemovedHeader(McpHeaders.SESSION_ID);
        return slots.computeIfAbsent(routingId, id -> new Slot()).issued(sessionless).admit(sessionless);
    }

    OpenedSessions opened() {
        return opened;
    }

    void deleteAll(Optional<String> liveSessionId) {
        opened.deleteAll(transport.http(), liveSessionId);
    }

    private Optional<IssuedSession> handshake(HttpRequest sessionless) {
        HttpRequestResponse initialize = handshake.initialize(sessionless);
        if (initialize == null) {
            return Optional.empty();
        }
        if (initialize.response().statusCode() / 100 != 2) {
            return Optional.of(IssuedSession.refused(initialize));
        }
        return Optional.of(SessionHeaders.issuedBy(initialize)
                .map(sessionId -> joined(sessionless, sessionId))
                .orElseGet(IssuedSession::stateless));
    }

    private IssuedSession joined(HttpRequest sessionless, String sessionId) {
        handshake.join(sessionless, sessionId, opened::record);
        return IssuedSession.joined(sessionId);
    }

    private final class Slot {

        private IssuedSession issued;

        synchronized IssuedSession issued(HttpRequest sessionless) {
            if (issued != null) {
                return issued;
            }
            IssuedSession handshaken = handshake(sessionless).orElseGet(() -> IssuedSession.refused(null));
            if (handshaken.settled()) {
                issued = handshaken;
            }
            return handshaken;
        }
    }
}
