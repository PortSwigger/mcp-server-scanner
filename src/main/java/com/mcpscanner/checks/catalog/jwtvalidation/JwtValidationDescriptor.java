package com.mcpscanner.checks.catalog.jwtvalidation;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;
import java.util.Optional;

final class JwtValidationDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "jwt-validation",
            "MCP JWT access token validation",
            "Replays one authenticated MCP tool call, resource read or prompt get with forged JWT bearer tokens: a random-key RS256 signature, "
                    + "alg: none, HS256 keyed with the published public key, and HS256 with an unknown key id and "
                    + "an empty secret. A forgery counts only when it returns the valid token's result while "
                    + "missing and malformed credentials are refused. Claim checks (iss, aud, exp) are then tested "
                    + "on the accepted forgery.",
            CheckKind.HOST,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-handling",
                    "https://datatracker.ietf.org/doc/html/rfc8725",
                    "https://datatracker.ietf.org/doc/html/rfc9068",
                    "https://portswigger.net/web-security/jwt"),
            Optional.of("JWT access token validation"),
            "An MCP server that accepts a JWT whose signature it did not verify lets anyone mint an access token "
                    + "with claims of their choosing, such as another user's subject, and reach the operations that "
                    + "token would authorise.",
            List.of(new Cwe(347, "Improper Verification of Cryptographic Signature"),
                    new Cwe(287, "Improper Authentication")));

    private JwtValidationDescriptor() {
    }
}
