package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.auth.AuthVariant;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.auth.oracle.OracleVerdict;
import com.mcpscanner.checks.shared.probe.IndependentSessionSender;
import com.mcpscanner.checks.shared.probe.NonexistentRouteControl;
import com.mcpscanner.checks.shared.probe.ProbeChannel;
import com.mcpscanner.checks.shared.probe.ProbeExchange;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class BypassSweep {

    private final SweepVariants variants;
    private final SweepMemo memo;
    private final IndependentSessionSender sender;
    private final ProbeChannel channel;
    private final BaselineEquivalenceOracle oracle;
    private final AnonymousRecheck anonymousRecheck;
    private final NonexistentRouteControl routeControl;

    BypassSweep(SweepVariants variants, SweepMemo memo, IndependentSessionSender sender, ProbeChannel channel,
                BaselineEquivalenceOracle oracle, AnonymousRecheck anonymousRecheck) {
        this.variants = variants;
        this.memo = memo;
        this.sender = sender;
        this.channel = channel;
        this.oracle = oracle;
        this.anonymousRecheck = anonymousRecheck;
        this.routeControl = new NonexistentRouteControl(sender, oracle);
    }

    Optional<Finding> sweep(AuditSubject subject, List<ProbeExchange> refusedControls) {
        for (AuthVariant variant : memo.pending(subject, variants.variantsFor(subject.seed()))) {
            if (channel.exhausted()) {
                return Optional.empty();
            }
            Optional<Finding> finding = probe(subject, refusedControls, variant);
            if (finding.isPresent()) {
                return finding;
            }
        }
        return Optional.empty();
    }

    private Optional<Finding> probe(AuditSubject subject, List<ProbeExchange> refusedControls, AuthVariant variant) {
        ProbeExchange candidate = sender.send(variant.candidate().applyTo(subject.seed()));
        OracleVerdict verdict = oracle.judgeUncontrolled(subject.baseline(), candidate.last());
        if (verdict != OracleVerdict.BASELINE_NOT_SUCCESSFUL) {
            memo.observe(subject, variant, candidate, refusedControls);
        }
        if (!verdict.isHit()) {
            return Optional.empty();
        }
        Optional<ProbeExchange> variantControl = routeControl.sendFor(variant.control(), subject.seed());
        if (routeControl.suppresses(variantControl)) {
            return Optional.empty();
        }
        if (anonymousRecheck.stillRefused(subject).isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new Finding(kindOf(variant), subject, variant.name(), variant.candidate().value(),
                evidenceOf(subject, refusedControls.get(0), variantControl, candidate)));
    }

    private static FindingKind kindOf(AuthVariant variant) {
        return RetainedSessionVariant.isRetainedSession(variant)
                ? FindingKind.SESSION_CREDENTIAL : FindingKind.AUTHENTICATION_BYPASS;
    }

    private static List<HttpRequestResponse> evidenceOf(AuditSubject subject, ProbeExchange refusedAnonymous,
                                                        Optional<ProbeExchange> variantControl,
                                                        ProbeExchange candidate) {
        List<HttpRequestResponse> evidence = new ArrayList<>(List.of(subject.baseline(), refusedAnonymous.answer()));
        variantControl.ifPresent(control -> evidence.add(control.answer()));
        evidence.add(candidate.answer());
        return evidence;
    }
}
