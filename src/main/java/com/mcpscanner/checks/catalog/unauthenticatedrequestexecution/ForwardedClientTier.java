package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.auth.AuthVariant;
import com.mcpscanner.checks.shared.auth.AuthVariantGenerator;
import com.mcpscanner.checks.shared.auth.RequestMutation;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.probe.AuthenticatedBaseline;
import com.mcpscanner.checks.shared.probe.McpMethodClass;
import com.mcpscanner.checks.shared.probe.ProbeChannel;
import com.mcpscanner.checks.shared.probe.ServerErrorAnswer;

import com.mcpscanner.mcp.TooManyRequests;
import java.util.List;
import java.util.Optional;
import java.util.Set;

final class ForwardedClientTier {

    private static final Set<McpMethodClass> PROBED = Set.of(McpMethodClass.OPERATION, McpMethodClass.CATALOG);
    private static final int FIRST_CLIENT_ERROR = 400;
    private static final int LAST_CLIENT_ERROR = 499;

    private final AuthVariantGenerator clientAddresses;
    private final AuthenticatedBaseline authenticated;
    private final ProbeChannel channel;
    private final BaselineEquivalenceOracle oracle;
    private final ScopeClaims judged;

    ForwardedClientTier(AuthVariantGenerator clientAddresses, AuthenticatedBaseline authenticated, ProbeChannel channel,
                        BaselineEquivalenceOracle oracle, ScopeClaims judged) {
        this.clientAddresses = clientAddresses;
        this.authenticated = authenticated;
        this.channel = channel;
        this.oracle = oracle;
        this.judged = judged;
    }

    Optional<Finding> judge(AuditSubject subject) {
        if (!PROBED.contains(subject.methodClass()) || !oracle.successful(subject.baseline())
                || !judged.claim(SweepScope.of(subject))) {
            return Optional.empty();
        }
        return clientAddresses.variantsFor(subject.seed()).stream()
                .takeWhile(variant -> !channel.exhausted())
                .map(variant -> probe(subject, variant))
                .flatMap(Optional::stream)
                .findFirst();
    }

    private Optional<Finding> probe(AuditSubject subject, AuthVariant variant) {
        RequestMutation external = variant.control().orElseThrow();
        HttpRequestResponse refused = send(subject, external);
        if (!turnedAway(refused)) {
            return Optional.empty();
        }
        HttpRequestResponse admitted = send(subject, variant.candidate());
        if (!oracle.judgeUncontrolled(subject.baseline(), admitted).isHit()) {
            return Optional.empty();
        }
        HttpRequestResponse refusedAgain = send(subject, external);
        if (!turnedAway(refusedAgain)) {
            return Optional.empty();
        }
        return Optional.of(new Finding(FindingKind.FORWARDED_CLIENT_ADDRESS_TRUSTED, subject, variant.name(),
                variant.candidate().value(), List.of(subject.baseline(), refused, admitted)));
    }

    private HttpRequestResponse send(AuditSubject subject, RequestMutation mutation) {
        return channel.send(mutation.applyTo(authenticated.requestFor(subject.seed())));
    }

    private boolean turnedAway(HttpRequestResponse exchange) {
        if (exchange == null || exchange.response() == null || oracle.successful(exchange)) {
            return false;
        }
        int status = exchange.response().statusCode();
        if (TooManyRequests.answered(exchange) || ServerErrorAnswer.of(exchange)) {
            return false;
        }
        return oracle.refused(exchange) || status >= FIRST_CLIENT_ERROR && status <= LAST_CLIENT_ERROR;
    }
}
