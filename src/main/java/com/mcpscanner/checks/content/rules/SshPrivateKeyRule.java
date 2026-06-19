package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.regex.Pattern;

public final class SshPrivateKeyRule extends RegexContentRule {

    // Require at least one base64 body line after the header so a description that merely names
    // the PEM header format (no key material) does not fire. The body line is matched on its own
    // line to avoid swallowing prose that follows the header on the same line.
    private static final Pattern SSH_KEY = Pattern.compile(
            "-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"
                    + "(?:[\\t ]*\\r?\\n)++[A-Za-z0-9+/]{32,}={0,2}");

    public SshPrivateKeyRule() {
        super(SSH_KEY);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.ssh-private-key";
    }

    @Override
    public String displayName() {
        return "SSH Private Keys";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.HIGH;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL;
    }
}
