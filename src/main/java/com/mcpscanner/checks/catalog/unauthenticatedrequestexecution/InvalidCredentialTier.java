package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import com.mcpscanner.checks.shared.auth.AuthVariant;
import com.mcpscanner.checks.shared.auth.AuthVariantSuite;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.probe.IndependentSessionSender;
import com.mcpscanner.checks.shared.probe.McpMethodClass;
import com.mcpscanner.checks.shared.probe.ProbeExchange;

import java.util.List;
import java.util.Optional;
import java.util.Set;

final class InvalidCredentialTier {

    private static final Set<McpMethodClass> REPORTED = Set.of(McpMethodClass.OPERATION, McpMethodClass.CATALOG);

    private final AuthVariantSuite suite;
    private final IndependentSessionSender sender;
    private final AnonymousRecheck anonymousRecheck;
    private final BaselineEquivalenceOracle oracle;
    private final EmbeddedErrorResult embeddedError = new EmbeddedErrorResult();

    InvalidCredentialTier(AuthVariantSuite suite, IndependentSessionSender sender, AnonymousRecheck anonymousRecheck,
                          BaselineEquivalenceOracle oracle) {
        this.suite = suite;
        this.sender = sender;
        this.anonymousRecheck = anonymousRecheck;
        this.oracle = oracle;
    }

    Optional<Finding> judge(AuditSubject subject, ProbeExchange refusedAnonymous, ProbeExchange malformed) {
        if (!subject.credentialsConfigured() || !REPORTED.contains(subject.methodClass())
                || embeddedError.carriedBy(subject.baseline()) || !reproducesBaseline(subject, malformed)) {
            return Optional.empty();
        }
        AuthVariant fabricated = suite.fabricatedCredential();
        ProbeExchange confirmation = sender.sendConfirmingRefusalInAFreshSession(
                fabricated.candidate().applyTo(subject.seed()));
        if (!reproducesBaseline(subject, confirmation)) {
            return Optional.empty();
        }
        if (anonymousRecheck.stillRefused(subject).isEmpty()) {
            return Optional.empty();
        }
        AuthVariant malformedVariant = suite.malformedCredentialControl();
        return Optional.of(new Finding(FindingKind.INVALID_CREDENTIAL_ACCEPTED, subject,
                malformedVariant.name() + ", " + fabricated.name(),
                malformedVariant.candidate().value() + ", " + fabricated.candidate().value(),
                List.of(subject.baseline(), refusedAnonymous.answer(), malformed.answer())));
    }

    private boolean reproducesBaseline(AuditSubject subject, ProbeExchange candidate) {
        return oracle.judgeUncontrolled(subject.baseline(), candidate.last()).isHit();
    }
}
