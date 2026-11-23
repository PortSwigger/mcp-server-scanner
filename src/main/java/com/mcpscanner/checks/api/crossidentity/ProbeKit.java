package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.session.SessionHeaders;

import java.util.Optional;
import java.util.concurrent.Executor;

public record ProbeKit(OperationSeed seed, Principal owner, PrincipalRequests requests, PrincipalSessions sessions,
                       ProbeTransport transport, ProbeTriplet triplet, AbsentValues absent, DecisionLog log,
                       OpenedSessions opened) {

    public static ProbeKit of(OperationSeed seed, Principal owner, PrincipalRequests requests, ProbeTransport transport,
                              AbsentValues absent, DecisionLog log, OpenedSessions opened) {
        return new ProbeKit(seed, owner, requests, new PrincipalSessions(seed, transport, opened), transport,
                new ProbeTriplet(transport, log), absent, log, opened);
    }

    public ProbeKit forPrincipal(Principal principal) {
        DecisionLog principalLog = log.about(principal.name());
        ProbeTransport principalTransport = transport.withFreshBudget(principalLog);
        return new ProbeKit(seed, owner, requests, new PrincipalSessions(seed, principalTransport, opened),
                principalTransport, triplet.over(principalTransport, principalLog), absent, principalLog, opened);
    }

    public ProbeKit armsOn(Executor arms) {
        return new ProbeKit(seed, owner, requests, sessions, transport, triplet.armsOn(arms), absent, log, opened);
    }

    public OperationReply reply(HttpRequest request) {
        return OperationReply.of(transport.send(request));
    }

    public Optional<HttpRequest> ownerRequest() {
        HttpRequest routed = requests.as(owner, seed.request());
        if (!owner.id().equals(Principal.PRIMARY_ID)) {
            return sessions.owned(routed);
        }
        return Optional.of(inCapturedSession(routed).orElse(routed));
    }

    public Optional<HttpRequest> inCapturedSession(HttpRequest request) {
        return seed.sessionId().map(sessionId -> SessionHeaders.inSession(request, sessionId));
    }

    public String ownerMarker() {
        return Markers.of(owner.privateMarker());
    }

    public boolean confirms(OperationReply reply, String marker) {
        return reply.contains(marker) && !Markers.mentionedBy(seed.request(), marker)
                && !Markers.mentionedBy(reply.exchange().request(), marker);
    }

    public void skippedUnlessStopped(SkipReason reason) {
        if (!transport.stopped()) {
            log.notRun(reason);
        }
    }

    public HttpRequest anonymousSessionless() {
        return requests.anonymous(seed.request());
    }
}
