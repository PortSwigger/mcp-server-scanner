package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;
import java.util.regex.Pattern;

public final class AwsAccessKeyRule extends HighEntropyCredentialRule {

    private static final Pattern AWS_ACCESS_KEY = Pattern.compile("(AKIA|ASIA)[A-Z2-7]{16}");
    private static final String AWS_CANONICAL_EXAMPLE = "AKIAIOSFODNN7EXAMPLE";

    // The 16-char base32 body is the shortest, smallest-alphabet credential we scan, so genuine
    // random keys can dip to ~2.6 bits/char. A 2.3 floor still rejects shaped filler (repeated
    // characters score well under 1.0) without clipping the lower tail of real keys.
    private static final double AWS_MIN_ENTROPY_BITS_PER_CHAR = 2.3;

    public AwsAccessKeyRule() {
        super(AWS_ACCESS_KEY);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.aws-access-key";
    }

    @Override
    public String displayName() {
        return "AWS Access Keys";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.HIGH;
    }

    @Override
    protected boolean isKnownPlaceholder(String match) {
        return AWS_CANONICAL_EXAMPLE.equals(match);
    }

    @Override
    protected double minEntropyBitsPerChar() {
        return AWS_MIN_ENTROPY_BITS_PER_CHAR;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html"));
    }
}
