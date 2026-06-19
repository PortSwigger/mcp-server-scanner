package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public final class GoogleApiKeyRule extends HighEntropyCredentialRule {

    private static final Pattern GOOGLE_KEY = Pattern.compile("AIza[A-Za-z0-9_-]{35}");

    private static final Set<String> CANONICAL_EXAMPLE_KEYS = Set.of(
            // Google Maps quickstart key, widely embedded across docs and tutorials.
            "AIzaSyClzfrOzB818x55FASHvX4JuGQciR9lv7q");

    public GoogleApiKeyRule() {
        super(GOOGLE_KEY);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.google-api-key";
    }

    @Override
    public String displayName() {
        return "Google API Keys";
    }

    @Override
    public AuditIssueSeverity severity() {
        // The AIza+35 shape is ubiquitous in docs and tutorials and carries no liveness or
        // secondary anchor, so a regex match alone does not justify HIGH.
        return AuditIssueSeverity.MEDIUM;
    }

    @Override
    protected boolean isKnownPlaceholder(String match) {
        return CANONICAL_EXAMPLE_KEYS.contains(match);
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://cloud.google.com/docs/authentication/api-keys"));
    }
}
