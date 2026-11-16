package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.mcp.McpRequestNames;

import java.util.stream.Collectors;

final class SqlInjectionIssues {


    static final String ISSUE_NAME = "MCP SQL injection";

    private static final String OBSERVATION = "For each technique, rewriting the value with SQL syntax that leaves "
            + "a spliced statement unchanged reproduced the baseline reply exactly, while a falsifier made of the "
            + "same characters in an order that breaks SQL changed it. Both rewrites have the same length and "
            + "characters, so a filter, length limit or reflection cannot tell them apart. At least one technique "
            + "uses syntax only SQL gives that meaning (a -- line comment or backtick identifier quoting). The "
            + "baseline value resent three times reproduced the baseline, and three repeats with fresh tokens agreed.";

    private static final String TENTATIVE_NOTE = "Only one family of SQL syntax separated the replies, so the "
            + "finding is tentative: confirm that the value reaches a SQL statement.";

    private static final String REMEDIATION = new IssueBodyBuilder()
            .paragraph("Pass MCP request values to the database only as bound query parameters. Where a value must "
                    + "name a table, column or database, check it against the names the schema actually has, or a "
                    + "strict identifier pattern, and quote it with the driver's identifier-quoting function.")
            .paragraph("Do not rely on a read-only mode or an approval prompt that inspects only the intended "
                    + "statement; a spliced value can append or rewrite statements.")
            .build();

    private final String background;

    SqlInjectionIssues(CheckDescriptor descriptor) {
        this.background = IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                descriptor.references());
    }

    AuditIssue render(Finding finding, HttpRequest baseRequest, String fieldName) {
        return AuditIssue.auditIssue(ISSUE_NAME, detail(finding, baseRequest, fieldName), REMEDIATION,
                baseRequest.url(), AuditIssueSeverity.HIGH, finding.confidence(), background, REMEDIATION,
                AuditIssueSeverity.HIGH, finding.evidence().toArray(HttpRequestResponse[]::new));
    }

    private static String detail(Finding finding, HttpRequest baseRequest, String fieldName) {
        IssueBodyBuilder body = new IssueBodyBuilder()
                .paragraph("Operation: " + new McpRequestNames().nameOf(baseRequest) + "; field: " + fieldName + ".")
                .paragraph("Rewritten: " + finding.slot().described() + ". Techniques: " + techniques(finding) + ".")
                .paragraph(OBSERVATION);
        if (finding.confidence() == AuditIssueConfidence.TENTATIVE) {
            body.paragraph(TENTATIVE_NOTE);
        }
        return body.paragraph("The requests and responses are, in order: the baseline, each technique's equivalent "
                        + "rewrite and falsifier, then three confirmation rounds each holding the baseline value resent "
                        + "and the first SQL-specific technique repeated with a fresh token.")
                .build();
    }

    private static String techniques(Finding finding) {
        return finding.forms().stream().map(SyntaxForm::technique).collect(Collectors.joining("; "));
    }
}
