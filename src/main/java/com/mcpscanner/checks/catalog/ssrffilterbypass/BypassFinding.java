package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.collaborator.ObservedInteractions;

import java.util.List;

record BypassFinding(HttpRequestResponse base, FetchField field, Refusal refusal, List<ControlledLead> proven,
                     ObservedInteractions observed, TargetPage page) {

    boolean showsTargetPage() {
        return !page.shownIn(refusal.evidence()) && proven.stream().anyMatch(this::showsPage);
    }

    ControlledLead attachedLead() {
        return proven.stream().filter(lead -> showsTargetPage() && showsPage(lead)).findFirst()
                .orElse(proven.get(0));
    }

    private boolean showsPage(ControlledLead lead) {
        return page.shownIn(lead.lead().loopback());
    }
}
