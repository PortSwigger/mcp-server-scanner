package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;
import java.util.regex.Pattern;

public final class GithubPatRule extends HighEntropyCredentialRule {

    private static final Pattern CLASSIC = Pattern.compile("gh[pousr]_[A-Za-z0-9]{36}");
    private static final Pattern FINE_GRAINED = Pattern.compile("github_pat_[A-Za-z0-9_]{82}");

    public GithubPatRule() {
        super(CLASSIC, FINE_GRAINED);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.github-pat";
    }

    @Override
    public String displayName() {
        return "GitHub Personal Access Tokens";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.HIGH;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/"));
    }
}
