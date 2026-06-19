package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.regex.Pattern;

public final class PgpPrivateKeyRule extends RegexContentRule {

    // Require at least one base64 body line after the armor header (optionally separated by armor
    // headers / a blank line) so a description that merely names the header does not fire.
    private static final Pattern PGP_KEY = Pattern.compile(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----"
                    + "(?:[\\t ]*\\r?\\n[ \\t]*[^\\r\\n:]+:[^\\r\\n]*)*"
                    + "(?:[\\t ]*\\r?\\n)++[A-Za-z0-9+/]{32,}={0,2}");

    public PgpPrivateKeyRule() {
        super(PGP_KEY);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.pgp-private-key";
    }

    @Override
    public String displayName() {
        return "PGP Private Keys";
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
