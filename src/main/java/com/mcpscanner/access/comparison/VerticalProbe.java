package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.crossidentity.OperationReply;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

final class VerticalProbe {

    private final PrincipalProbe probe;
    private final PrincipalListings listings;

    VerticalProbe(PrincipalProbe probe, PrincipalListings listings) {
        this.probe = probe;
        this.listings = listings;
    }

    boolean run(IdentityReach reach) {
        return reportReached(reach, "operation_level:disallowed_identity_reached", this::disallowedObservation,
                List.of(reach.finalReply()));
    }

    boolean runRefusedAtCapturedVersion(IdentityReach reach, OperationReply capturedRefusal) {
        return reportReached(reach, "operation_level:refused_at_captured_protocol_version",
                this::versionGatedObservation, List.of(capturedRefusal, reach.finalReply()));
    }

    private boolean reportReached(IdentityReach reach, String decision, Observation observation,
                                  List<OperationReply> identityReplies) {
        if (!reach.ownerResultReached()) {
            return false;
        }
        if (!probe.anonymous().refused()) {
            return probe.rejected("operation_level:anonymous_not_refused");
        }
        boolean hidden = listings.lists(probe.principal().id(), probe.kit().seed().item()).equals(Optional.of(false));
        boolean marker = probe.ownerMarkerConfirms(reach.finalReply());
        probe.decide(decision);
        probe.report(FindingKind.OPERATION_AVAILABLE, "operation", hidden || marker,
                observation.describe(reach, hidden, marker), evidence(identityReplies));
        return true;
    }

    private List<HttpRequestResponse> evidence(List<OperationReply> identityReplies) {
        return Stream.concat(Stream.of(probe.owner(), probe.anonymous().reply()), identityReplies.stream())
                .map(OperationReply::exchange).toList();
    }

    private String versionGatedObservation(IdentityReach reach, boolean hidden, boolean marker) {
        String identity = probe.principal().name();
        StringBuilder text = new StringBuilder(identity + "'s credentials" + reach.variant().retryNote()
                + " returned exactly the owner's result for " + probe.kit().seed().label()
                + ", although the same call is refused at the captured protocol version, while the anonymous "
                + "request was refused. The server enforces access differently depending on the protocol version.");
        appendConfirmations(text, identity, hidden, marker);
        return text.toString();
    }

    private String disallowedObservation(IdentityReach reach, boolean hidden, boolean marker) {
        String identity = probe.principal().name();
        StringBuilder text = new StringBuilder(identity + "'s credentials" + reach.variant().retryNote()
                + " returned exactly the owner's result for "
                + probe.kit().seed().label() + ", which the access expectation for this item does not allow for "
                + "that identity, while the anonymous request was refused.");
        appendConfirmations(text, identity, hidden, marker);
        if (!hidden && !marker) {
            text.append(" The item is listed for that identity and no private marker confirmed the result: review "
                    + "whether the expectation is right.");
        }
        return text.toString();
    }

    private static void appendConfirmations(StringBuilder text, String identity, boolean hidden, boolean marker) {
        if (hidden) {
            text.append(" The item is absent from ").append(identity).append("'s own listing.");
        }
        if (marker) {
            text.append(" The owner's private marker, absent from every request sent, appeared in that result.");
        }
    }

    @FunctionalInterface
    private interface Observation {
        String describe(IdentityReach reach, boolean hidden, boolean marker);
    }
}
