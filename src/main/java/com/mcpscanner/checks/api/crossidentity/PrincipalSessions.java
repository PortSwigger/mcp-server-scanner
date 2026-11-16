package com.mcpscanner.checks.api.crossidentity;

import com.mcpscanner.checks.shared.session.SessionHeaders;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.McpHeaders;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

public final class PrincipalSessions {

    private final OperationSeed seed;
    private final SessionHandshake handshake;
    private final OpenedSessions opened;

    public PrincipalSessions(OperationSeed seed, ProbeTransport transport, OpenedSessions opened) {
        this.seed = seed;
        this.handshake = new SessionHandshake(transport::send);
        this.opened = opened;
    }

    public Optional<HttpRequest> fresh(HttpRequest principalRequest) {
        return admit(principalRequest).request();
    }

    public SessionAdmission admit(HttpRequest principalRequest) {
        if (!seed.stateful()) {
            return SessionAdmission.admitted(principalRequest);
        }
        HttpRequest sessionless = principalRequest.withRemovedHeader(McpHeaders.SESSION_ID);
        return admitted(sessionless, () -> sessionless);
    }

    public Optional<HttpRequest> owned(HttpRequest ownerRequest) {
        return seed.stateful() ? disposable(ownerRequest) : Optional.of(ownerRequest);
    }

    public Optional<HttpRequest> disposable(HttpRequest ownerRequest) {
        HttpRequest sessionless = ownerRequest.withRemovedHeader(McpHeaders.SESSION_ID);
        return admitted(sessionless, () -> SessionHeaders.inSession(sessionless, chosenSessionId())).request();
    }

    public IssuedSession<HttpRequest> issued(HttpRequest principalRequest) {
        HttpRequest sessionless = principalRequest.withRemovedHeader(McpHeaders.SESSION_ID);
        HttpRequestResponse admission = handshake.initialize(sessionless);
        if (admission == null || admission.response().statusCode() / 100 != 2) {
            return IssuedSession.initializeFailed();
        }
        return SessionHeaders.issuedBy(admission)
                .map(sessionId -> IssuedSession.issued(handshake.join(sessionless, sessionId, opened::record)))
                .orElseGet(IssuedSession::noSessionIssued);
    }

    private SessionAdmission admitted(HttpRequest sessionless, Supplier<HttpRequest> withoutIssuedSession) {
        HttpRequestResponse admission = handshake.initialize(sessionless);
        if (admission == null || admission.response().statusCode() / 100 != 2) {
            return SessionAdmission.refused(admission);
        }
        return SessionAdmission.admitted(SessionHeaders.issuedBy(admission)
                .map(sessionId -> handshake.join(sessionless, sessionId, opened::record))
                .orElseGet(withoutIssuedSession));
    }

    private static String chosenSessionId() {
        return "mcp-scanner-" + UUID.randomUUID();
    }
}
