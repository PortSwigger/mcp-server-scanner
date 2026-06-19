package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;
import java.util.regex.Pattern;

public final class SlackTokenRule extends HighEntropyCredentialRule {

    private static final Pattern SLACK_BOT_USER = Pattern.compile(
            "xox[baprs]-\\d+-\\d+-[A-Za-z0-9]{24,}");
    private static final Pattern SLACK_APP = Pattern.compile(
            "xapp-\\d+-[A-Z0-9]+-\\d+-[a-f0-9]{40,}");
    private static final Pattern SLACK_REFRESH = Pattern.compile(
            "xoxe-\\d+-[A-Za-z0-9]{20,}");

    public SlackTokenRule() {
        super(SLACK_BOT_USER, SLACK_APP, SLACK_REFRESH);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.slack-token";
    }

    @Override
    public String displayName() {
        return "Slack Tokens";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.HIGH;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://api.slack.com/authentication/token-types"));
    }
}
