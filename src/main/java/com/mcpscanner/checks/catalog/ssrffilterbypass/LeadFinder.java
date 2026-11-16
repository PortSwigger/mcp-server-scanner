package com.mcpscanner.checks.catalog.ssrffilterbypass;

import com.mcpscanner.checks.api.SkipReason;

import java.util.List;
import java.util.Optional;

final class LeadFinder {

    static final SkipReason NO_REPLY = SkipReason.transportFailure("the dotted loopback probe got no reply");
    static final SkipReason NO_FILTER = SkipReason.notApplicable(
            "loopback URLs on two ports were not refused alike, so no address filter was shown");
    static final SkipReason REFUSAL_CHANGED = SkipReason.notApplicable(
            "the loopback refusal changed while the spellings were sent, so a changed reply is not evidence");

    private static final String DOTTED_LOOPBACK = Ipv4Literal.LOOPBACK.dotted();
    private static final int CLOSED_PORT = 1;

    private final FieldSender sender;
    private final int targetPort;

    LeadFinder(FieldSender sender, int targetPort) {
        this.sender = sender;
        this.targetPort = targetPort;
    }

    LeadSearch search() {
        SentUrl first = sender.send(ProbeUrl.loopback(DOTTED_LOOPBACK, targetPort));
        if (!first.answered()) {
            return LeadSearch.stopped(NO_REPLY);
        }
        Optional<Refusal> refusal = Refusal.confirmedBy(first,
                sender.send(ProbeUrl.loopback(DOTTED_LOOPBACK, CLOSED_PORT)));
        return refusal.map(this::leadsPast).orElseGet(() -> LeadSearch.stopped(NO_FILTER));
    }

    private LeadSearch leadsPast(Refusal refusal) {
        List<Lead> leads = Lead.find(sender, targetPort, refusal);
        if (!leads.isEmpty() && !refusal.repeatedBy(sender.send(refusal.evidence().probe()))) {
            return LeadSearch.stopped(REFUSAL_CHANGED);
        }
        return LeadSearch.found(refusal, leads);
    }
}
