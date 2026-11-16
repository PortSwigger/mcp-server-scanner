package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.AbsentValues;
import com.mcpscanner.checks.api.crossidentity.AnonymousReply;
import com.mcpscanner.checks.api.crossidentity.DecisionLog;
import com.mcpscanner.checks.api.crossidentity.Markers;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.checks.api.crossidentity.OperationSeed;
import com.mcpscanner.checks.api.crossidentity.ProbeKit;
import com.mcpscanner.checks.api.crossidentity.ProbeTransport;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class IdentityFindings {

    static final String MARKER_REPLAY = "private-marker";

    private final OperationSeed seed;
    private final Principal owner;
    private final OperationReply ownerReply;
    private final AnonymousReply anonymous;
    private final ComparisonContext context;
    private final ProbeKit kit;
    private final AccessExpectation expectation;
    private final Outcomes outcomes;

    IdentityFindings(OperationSeed seed, Principal owner, OperationReply ownerReply, AnonymousReply anonymous,
                     ComparisonContext context, DecisionLog log, Outcomes outcomes) {
        this.outcomes = outcomes;
        this.seed = seed;
        this.owner = owner;
        this.ownerReply = ownerReply;
        this.anonymous = anonymous;
        this.context = context;
        this.kit = ProbeKit.of(seed, owner, context.requests(), new ProbeTransport(context.transport().http(), log),
                new AbsentValues(), log, context.sessions().opened());
        this.expectation = context.ports().expectations().expectationFor(seed.item());
    }

    List<Finding> of(Principal principal, Replay replay) {
        List<Finding> found = new ArrayList<>();
        PrincipalProbe probe = new PrincipalProbe(kit.forPrincipal(principal), principal, ownerReply, anonymous,
                found::add);
        if (reachedForbiddenOperation(probe, replay)) {
            return found;
        }
        if (ExpectationPolicy.comparesObjects(expectation, principal.role())) {
            compareOrConfirmMarker(probe, replay);
        }
        return found;
    }

    private boolean reachedForbiddenOperation(PrincipalProbe probe, Replay replay) {
        if (!expectation.forbids(probe.principal().role())) {
            outcomes.record(probe.principal(), Outcomes.compared(replay.reply(), ownerReply));
            return refusedOnlyAtCapturedVersion(probe, replay);
        }
        IdentityReach reach = new IdentityReplay(probe, replay).reach();
        outcomes.record(probe.principal(), Outcomes.compared(reach.finalReply(), ownerReply));
        return new VerticalProbe(probe, context.ports().listings()).run(reach);
    }

    private boolean refusedOnlyAtCapturedVersion(PrincipalProbe probe, Replay replay) {
        if (expectation == AccessExpectation.SHARED_BY_DESIGN) {
            return false;
        }
        IdentityReach reach = new IdentityReplay(probe, replay).atOlderVersions();
        if (!reach.ownerResultReached()) {
            return false;
        }
        outcomes.record(probe.principal(), Outcomes.compared(reach.finalReply(), ownerReply));
        return new VerticalProbe(probe, context.ports().listings()).runRefusedAtCapturedVersion(reach);
    }

    private boolean advertisedResource(PrincipalProbe probe) {
        boolean advertised = seed.item().kind() == AccessItemKey.Kind.RESOURCE
                && context.ports().listings().lists(probe.principal().id(), seed.item()).equals(Optional.of(true));
        if (advertised) {
            probe.decide("object_level:resource_listed_to_identity");
        }
        return advertised;
    }

    private void compareOrConfirmMarker(PrincipalProbe probe, Replay replay) {
        if (advertisedResource(probe)) {
            reportMarkerLeak(probe, replay.reply());
        } else {
            compareObjects(probe, replay);
        }
    }

    private boolean reportMarkerLeak(PrincipalProbe probe, OperationReply reply) {
        boolean leaked = leaks(reply);
        if (leaked) {
            probe.findings().accept(markerFinding(probe.principal(), reply));
        }
        return leaked;
    }

    private void compareObjects(PrincipalProbe probe, Replay replay) {
        OperationReply reply = replay.reply();
        if (!reportMarkerLeak(probe, reply) && ownerResult(reply)) {
            replay.request().ifPresent(new PeerReplayProbe(probe, referencesOf(owner))::run);
        }
        if (!probe.principal().ownedObjects().isEmpty()) {
            new ForeignReferenceProbe(probe, referencesOf(probe.principal())).run();
        }
    }

    private Map<String, String> referencesOf(Principal principal) {
        return context.ports().references().of(principal, seed.item());
    }

    private boolean ownerResult(OperationReply reply) {
        return reply.success() && ownerReply.sameResult(reply);
    }

    private boolean leaks(OperationReply reply) {
        String marker = Markers.of(owner.privateMarker());
        return kit.confirms(reply, marker) && !anonymous.reply().contains(marker);
    }

    private Finding markerFinding(Principal principal, OperationReply reply) {
        List<HttpRequestResponse> evidence = List.of(ownerReply.exchange(), reply.exchange(),
                anonymous.reply().exchange());
        return new Finding(FindingKind.RESULT_AVAILABLE, MARKER_REPLAY, AuditIssueConfidence.FIRM,
                principal.name() + "'s credentials returned a result for " + seed.label() + " containing "
                        + owner.name() + "'s private marker, while the anonymous request did not.",
                principal, evidence);
    }
}
