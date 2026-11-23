package com.mcpscanner.checks.catalog.sessionlifecycle;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.session.SessionRefusal;
import com.mcpscanner.core.connection.HttpProbeSession;
import com.mcpscanner.core.protocol.McpFlow;

import java.util.Optional;

final class DeletedSessionProbe {

    private static final int METHOD_NOT_ALLOWED = 405;

    private final SessionPing ping;
    private final SessionEnforcement enforcement;
    private final DeletedStreamProbe streams;
    private final ProbeTraffic traffic;
    private final SkipLog test;

    DeletedSessionProbe(SessionPing ping, SessionEnforcement enforcement, DeletedStreamProbe streams,
                        ProbeTraffic traffic, SkipLog test) {
        this.ping = ping;
        this.enforcement = enforcement;
        this.streams = streams;
        this.traffic = traffic;
        this.test = test;
    }

    Optional<DeletedSessionReuse> probe(HttpProbeSession session) {
        Optional<HttpRequestResponse> before = ping.answered(session);
        if (before.isEmpty()) {
            return skip(SkipReason.prerequisiteMissing("a fresh probe session did not answer ping"));
        }
        Optional<HttpRequestResponse> control = enforcement.unissuedId(session);
        if (control.filter(PingReplies::answered).isPresent()) {
            return skip(SkipReason.notApplicable(
                    "the server does not enforce Mcp-Session-Id (a never-issued ID answered ping)"));
        }
        Optional<HttpRequestResponse> refused = control.filter(SessionRefusal::refuses);
        if (refused.isEmpty()) {
            return skip(SkipReason.prerequisiteMissing("session-ID enforcement not established (a never-issued ID got "
                    + control.map(PingReplies::statusOf).orElse("no response") + ")"));
        }
        String deletedId = session.sessionId().orElseThrow();
        return terminate(session).flatMap(delete -> reuse(new DeletedSessionReuse(refused.get(), delete,
                ping.answered(session), streams.probe(deletedId, enforcement.unissuedId()))));
    }

    private static Optional<DeletedSessionReuse> reuse(DeletedSessionReuse observed) {
        return observed.answeredAfter().isPresent() || observed.streamAfter().isPresent()
                ? Optional.of(observed) : Optional.empty();
    }

    private Optional<HttpRequestResponse> terminate(HttpProbeSession session) {
        int mark = traffic.mark();
        McpFlow.HttpResponse response = session.terminate();
        if (response == null) {
            return skip(SkipReason.transportFailure("DELETE got no response"));
        }
        if (response.status() / 100 != 2) {
            return skip(SkipReason.notApplicable("the server answered DELETE with HTTP " + response.status()
                    + (response.status() == METHOD_NOT_ALLOWED ? " (clients cannot end sessions)" : "")));
        }
        return traffic.latestSince(mark);
    }

    private <T> Optional<T> skip(SkipReason reason) {
        test.notRun(reason, traffic);
        return Optional.empty();
    }
}
