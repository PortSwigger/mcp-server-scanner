package com.mcpscanner.checks.catalog.ssrffilterbypass;

import com.mcpscanner.checks.api.SkipReason;

import java.util.List;
import java.util.Optional;

record LeadSearch(Optional<SkipReason> stopped, Optional<Refusal> refusal, List<Lead> leads) {

    static LeadSearch stopped(SkipReason reason) {
        return new LeadSearch(Optional.of(reason), Optional.empty(), List.of());
    }

    static LeadSearch found(Refusal refusal, List<Lead> leads) {
        return new LeadSearch(Optional.empty(), Optional.of(refusal), List.copyOf(leads));
    }
}
