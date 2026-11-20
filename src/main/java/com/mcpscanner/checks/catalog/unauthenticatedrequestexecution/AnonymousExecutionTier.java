package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.probe.McpMethodClass;
import com.mcpscanner.checks.shared.probe.ProbeExchange;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class AnonymousExecutionTier {

    static final String VARIANT_NAME = "credential.none";

    private final BaselineEquivalenceOracle oracle;
    private final EnforcementEvidence enforcement;
    private final EnforcementProbe enforcementProbe;

    AnonymousExecutionTier(BaselineEquivalenceOracle oracle, EnforcementEvidence enforcement,
                           EnforcementProbe enforcementProbe) {
        this.oracle = oracle;
        this.enforcement = enforcement;
        this.enforcementProbe = enforcementProbe;
    }

    Optional<Finding> judge(AuditSubject subject, ProbeExchange anonymous) {
        McpMethodClass methodClass = subject.methodClass();
        if (!reported(methodClass) || !oracle.judgeUncontrolled(subject.baseline(), anonymous.last()).isHit()) {
            return Optional.empty();
        }
        List<HttpRequestResponse> evidence = new ArrayList<>(List.of(subject.baseline(), anonymous.answer()));
        if (methodClass == McpMethodClass.CATALOG) {
            return Optional.of(new Finding(FindingKind.ANONYMOUS_CATALOG, subject, VARIANT_NAME, "", evidence));
        }
        Optional<HttpRequestResponse> enforced = subject.credentialsConfigured()
                ? enforcement.find(subject, enforcementProbe) : Optional.empty();
        enforced.ifPresent(evidence::add);
        FindingKind kind = enforced.isPresent()
                ? FindingKind.ANONYMOUS_EXECUTION_DESPITE_ENFORCEMENT : FindingKind.ANONYMOUS_EXECUTION;
        return Optional.of(new Finding(kind, subject, VARIANT_NAME, "", evidence));
    }

    private static boolean reported(McpMethodClass methodClass) {
        return methodClass == McpMethodClass.OPERATION || methodClass == McpMethodClass.CATALOG;
    }
}
