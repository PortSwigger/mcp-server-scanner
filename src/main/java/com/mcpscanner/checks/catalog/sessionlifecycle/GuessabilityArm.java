package com.mcpscanner.checks.catalog.sessionlifecycle;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.catalog.sessionlifecycle.ids.IdAssessment;
import com.mcpscanner.checks.catalog.sessionlifecycle.ids.IdSample;
import com.mcpscanner.checks.catalog.sessionlifecycle.ids.SessionIdGuessability;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcEnvelope;
import com.mcpscanner.mcp.McpMethods;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

final class GuessabilityArm {

    static final int PROBE_SESSIONS = 8;
    static final int SHOWN_HANDSHAKES = 2;

    private final SessionIdGuessability guessability;
    private final CheckLog log;

    GuessabilityArm(SessionIdGuessability guessability, CheckLog log) {
        this.guessability = guessability;
        this.log = log;
    }

    <S extends AutoCloseable> Optional<GuessableIds> judge(ProbeSessionPool<S> pool, OpenedProbes<S> first,
                                                           ProbeTraffic traffic, String liveSessionId,
                                                           Function<OpenedProbes<S>, Optional<BareSessionUse>> bareUse) {
        OpenedProbes<S> probes = first;
        IdAssessment assessment = guessability.assess(probes.idSample());
        if (assessment.undecided()) {
            log.info("the first " + probes.issuedIds().size() + " session IDs were borderline; opening up to "
                    + IdSample.DECISIVE_SIZE + " probe sessions");
            probes = pool.openUpTo(IdSample.DECISIVE_SIZE);
            assessment = guessability.assess(probes.idSample());
        }
        if (assessment.weaknesses().isEmpty()) {
            return Optional.empty();
        }
        List<String> issuedIds = probes.issuedIds();
        List<HttpRequestResponse> handshakes = traffic.all().stream()
                .filter(GuessabilityArm::initialize)
                .flatMap(exchange -> HandshakeEvidence.of(exchange, issuedIds).stream())
                .limit(SHOWN_HANDSHAKES)
                .toList();
        return Optional.of(new GuessableIds(probes.issuedIds(), assessment.weaknesses(), handshakes,
                bareUse.apply(probes), probes.issuedIds().contains(liveSessionId)));
    }

    private static boolean initialize(HttpRequestResponse exchange) {
        return JsonRpcEnvelope.of(exchange.request()).method().filter(McpMethods.INITIALIZE::equals).isPresent();
    }
}
