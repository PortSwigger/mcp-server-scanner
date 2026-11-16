package com.mcpscanner.checks.catalog.ssrffilterbypass;

import com.mcpscanner.checks.shared.collaborator.InteractionListener;
import com.mcpscanner.checks.shared.collaborator.ObservedInteractions;
import com.mcpscanner.checks.shared.collaborator.WatchDecision;

import java.util.List;
import java.util.function.BiConsumer;

final class WatchedBypass implements InteractionListener {

    private final List<ControlledLead> leads;
    private final BiConsumer<List<ControlledLead>, ObservedInteractions> reporter;

    WatchedBypass(List<ControlledLead> leads, BiConsumer<List<ControlledLead>, ObservedInteractions> reporter) {
        this.leads = List.copyOf(leads);
        this.reporter = reporter;
    }

    @Override
    public WatchDecision interacted(ObservedInteractions soFar) {
        List<ControlledLead> proven = leads.stream().filter(lead -> lead.fetchedBy(soFar)).toList();
        if (proven.isEmpty()) {
            return WatchDecision.KEEP_WATCHING;
        }
        reporter.accept(proven, soFar);
        return WatchDecision.DONE;
    }
}
