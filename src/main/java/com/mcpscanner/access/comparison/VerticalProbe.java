package com.mcpscanner.access.comparison;

import com.mcpscanner.checks.api.PrincipalListings;

import java.util.List;
import java.util.Optional;

final class VerticalProbe {

    private final PrincipalProbe probe;
    private final PrincipalListings listings;

    VerticalProbe(PrincipalProbe probe, PrincipalListings listings) {
        this.probe = probe;
        this.listings = listings;
    }

    boolean run(IdentityReach reach) {
        return reportReached(reach, "operation_level:disallowed_identity_reached", this::disallowedObservation);
    }

    boolean runRefusedAtCapturedVersion(IdentityReach reach) {
        return reportReached(reach, "operation_level:refused_at_captured_protocol_version",
                this::versionGatedObservation);
    }

    private boolean reportReached(IdentityReach reach, String decision, Observation observation) {
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
                observation.describe(reach, hidden, marker),
                List.of(probe.owner().exchange(), probe.anonymous().reply().exchange(),
                        reach.finalReply().exchange()));
        return true;
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
