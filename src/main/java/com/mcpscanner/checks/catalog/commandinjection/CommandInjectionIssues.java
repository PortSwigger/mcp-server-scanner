package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.issue.Cwe;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.shared.collaborator.InteractionDescription;

import java.util.List;
import java.util.stream.Collectors;

final class CommandInjectionIssues {

    private static final String REMEDIATION = new IssueBodyBuilder()
            .paragraph("Pass MCP request values to subprocesses as separate argument-vector entries, never through "
                    + "a shell command string, and never pass them to eval, exec, Function or a template engine.")
            .paragraph("Put a -- separator before caller-supplied positional arguments, or reject values that "
                    + "start with a dash, so a value cannot be parsed as an option.")
            .paragraph("Where a tool must run code or commands by design, restrict who can call it and run it in a "
                    + "sandbox without network access.")
            .build();

    private final String background;

    CommandInjectionIssues(String backgroundProse, List<Cwe> cwes, List<String> references) {
        this.background = IssueMetadataRenderer.background(backgroundProse, cwes, references);
    }

    AuditIssue render(Finding finding) {
        FindingKind kind = finding.kind();
        return AuditIssue.auditIssue(kind.issueName(), detail(finding), REMEDIATION,
                finding.subject().url(), kind.severity(), kind.confidence(), background, REMEDIATION, kind.severity(),
                finding.evidence().toArray(HttpRequestResponse[]::new));
    }

    private static String detail(Finding finding) {
        FieldSubject subject = finding.subject();
        IssueBodyBuilder body = new IssueBodyBuilder()
                .paragraph("Operation: " + subject.operation() + "; field: " + subject.field() + ".")
                .paragraph("Technique: " + finding.technique() + ".")
                .paragraph(finding.kind().observation());
        if (!finding.interactions().isEmpty()) {
            body.paragraph(interactionsParagraph(finding.interactions()));
        }
        return body.paragraph("The requests and responses are, in order, the evidence named above; the first is the "
                        + "baseline where one was compared.")
                .build();
    }

    private static String interactionsParagraph(List<Interaction> interactions) {
        return interactions.stream().map(InteractionDescription::of)
                .collect(Collectors.joining("; ", "Collaborator interactions: ", "."));
    }
}
