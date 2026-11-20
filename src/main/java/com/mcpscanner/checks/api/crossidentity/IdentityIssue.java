package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.issue.Cwe;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;

import java.util.List;
import java.util.Objects;

public record IdentityIssue(String name, AuditIssueSeverity severity, AuditIssueConfidence confidence,
                            String background, String strength, IdentityObservation observation) {

    public static final String REMEDIATION = "Bind every MCP tool and resource dispatch to the authenticated "
            + "principal: check object ownership or tenant membership and the required role or scope on each call, "
            + "and never treat an Mcp-Session-Id as a credential or let another principal's credential rebind a "
            + "session.";

    public static ConsolidationAction consolidate(AuditIssue existing, AuditIssue candidate) {
        return IssueIdentity.keepStrongerOfSameSubject(existing, candidate);
    }

    public AuditIssue render(OperationSeed seed, ReplayedOperation replayed, CheckDescriptor descriptor) {
        return render(seed, replayed, descriptor.cwes(), descriptor.references());
    }

    public AuditIssue render(OperationSeed seed, ReplayedOperation replayed, List<Cwe> cwes,
                             List<String> references) {
        return AuditIssue.auditIssue(name, detail(seed, replayed), REMEDIATION, seed.request().url(), severity, confidence,
                IssueMetadataRenderer.background(background, cwes, references),
                "", severity, evidence().toArray(HttpRequestResponse[]::new));
    }

    private List<HttpRequestResponse> evidence() {
        return observation.evidence().stream().filter(Objects::nonNull).toList();
    }

    private String detail(OperationSeed seed, ReplayedOperation replayed) {
        Principal principal = observation.principal();
        return new IssueBodyBuilder()
                .paragraph("MCP operation: " + seed.label() + ". Identity: " + principal.name() + " ("
                        + principal.role().label() + "). Probe: " + observation.family() + ".")
                .paragraph(observation.text())
                .paragraph(strength)
                .paragraph(replayed.probeContract())
                .build();
    }
}
