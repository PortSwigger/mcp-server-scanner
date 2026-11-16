package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.shared.collaborator.InteractionDescription;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class SsrfFilterBypassIssues {

    static final String NAME = "MCP server SSRF address filter bypass";
    private static final String REFUSED = "The server refused the loopback URL %s with a reply that did not change "
            + "with the port, which shows an address filter.";
    private static final String BYPASSED = "These spellings of the same loopback address were not refused, and the "
            + "same spelling of the Burp Collaborator address was fetched, so the server parses the spelling and "
            + "its filter does not recognise it:";
    private static final String PAGE_SHOWN = "The reply to the loopback probe contains the target's own page, so the "
            + "server fetched the internal address and returned its content.";
    private static final String TENTATIVE = "The scanner cannot see what the server reached at the loopback address, "
            + "only that the filter no longer refused it. Confirm by requesting an internal service the server "
            + "can reach.";
    private static final String REMEDIATION = "Parse the URL with the same parser the HTTP client uses, resolve the "
            + "host, and check every resolved address (including IPv4-mapped IPv6) against private, loopback, "
            + "link-local and unspecified ranges before connecting. Connect to the checked address so a second "
            + "resolution cannot change it, and apply the same check to every redirect.";

    private final CheckDescriptor descriptor;

    SsrfFilterBypassIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue issue(BypassFinding finding) {
        boolean firm = finding.showsTargetPage();
        return AuditIssue.auditIssue(NAME, detail(finding, firm), REMEDIATION, finding.base().request().url(),
                descriptor.headlineSeverity(), firm ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE,
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null, descriptor.headlineSeverity(), exchanges(finding));
    }

    private static String detail(BypassFinding finding, boolean firm) {
        return new IssueBodyBuilder()
                .paragraph("Field: " + finding.field().subject())
                .paragraph(String.format(REFUSED, finding.refusal().evidence().url()))
                .paragraph(BYPASSED)
                .findings(finding.proven().stream().map(lead -> describe(lead, finding)).toList())
                .paragraph(firm ? PAGE_SHOWN : TENTATIVE)
                .build();
    }

    private static String describe(ControlledLead lead, BypassFinding finding) {
        String interactions = finding.observed().of(lead.payload()).stream().map(InteractionDescription::of)
                .collect(Collectors.joining("; "));
        return lead.lead().spelling().label() + ": " + lead.lead().loopback().url() + " was not refused; "
                + lead.control().url() + " was fetched (" + interactions + ")";
    }

    private static List<HttpRequestResponse> exchanges(BypassFinding finding) {
        return new ArrayList<>(Stream.concat(Stream.of(finding.refusal().evidence().exchange()),
                finding.proven().stream().flatMap(lead -> Stream.of(lead.lead().loopback().exchange(),
                        lead.control().exchange()))).toList());
    }
}
