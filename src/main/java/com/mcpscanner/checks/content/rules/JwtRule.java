package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.ContentSuppression;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public final class JwtRule extends RegexContentRule {

    private static final Pattern JWT = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]*");

    // A live JWT's signature is a base64url-encoded HMAC/RSA digest — dense randomness scoring
    // ~5 bits/char. Sample/alg:none tokens carry an empty or trivially-shaped signature, so
    // gating on the signature segment's entropy drops documentation tokens without dropping
    // realistic ones. 3.0 sits in the empty gap between the two distributions.
    private static final double MIN_SIGNATURE_ENTROPY_BITS_PER_CHAR = 3.0;

    private static final Set<String> CANONICAL_EXAMPLE_TOKENS = Set.of(
            // jwt.io homepage example token — widely embedded in docs and tutorials.
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
                    + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            // RFC 7519 §3.1 example token (Joe's JWT).
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
                    + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                    + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );

    public JwtRule() {
        super(JWT);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.jwt";
    }

    @Override
    public String displayName() {
        return "JWT Tokens";
    }

    @Override
    public AuditIssueSeverity severity() {
        // A regex match cannot confirm a live, unexpired, validly-signed token (no signature
        // or liveness verification), so this stays informational — aligned with Email/PrivateIp.
        return AuditIssueSeverity.INFORMATION;
    }

    @Override
    public AuditIssueConfidence confidence() {
        return AuditIssueConfidence.TENTATIVE;
    }

    @Override
    protected boolean isSuppressedMatch(String match) {
        return CANONICAL_EXAMPLE_TOKENS.contains(match) || hasLowEntropySignature(match);
    }

    private static boolean hasLowEntropySignature(String token) {
        int lastDot = token.lastIndexOf('.');
        String signature = lastDot < 0 ? "" : token.substring(lastDot + 1);
        return ContentSuppression.shannonEntropy(signature) < MIN_SIGNATURE_ENTROPY_BITS_PER_CHAR;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://www.rfc-editor.org/rfc/rfc7519"));
    }
}
