package com.mcpscanner.checks.catalog.jwtvalidation;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;

import java.util.ArrayList;
import java.util.List;

final class JwtValidationIssues {

    private final CheckDescriptor descriptor;

    JwtValidationIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue create(ForgedTokenFindings findings) {
        HttpRequestResponse baseline = findings.baseline();
        return AuditIssue.auditIssue(descriptor.issueName(), detail(findings), remediation(),
                baseline.request().url(), descriptor.headlineSeverity(), descriptor.headlineConfidence(),
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null, descriptor.headlineSeverity(), evidence(findings));
    }

    private static String detail(ForgedTokenFindings findings) {
        IssueBodyBuilder body = new IssueBodyBuilder()
                .paragraph("The MCP server accepted JWT access tokens that it should have rejected. The request "
                        + "succeeded with the scanner's valid token and was refused both without a credential and "
                        + "with a malformed bearer token, before and again after each forged token. Each of the "
                        + "following tokens, carrying the valid token's claims, returned the same successful result "
                        + "as the valid token:")
                .findings(findings.acceptedForgeries().stream().map(AcceptedForgery::description).toList());
        appendClaimProbes(body, findings.claimProbes());
        body.paragraph("The repeated request is a tool call, resource read or prompt get, and the forged token's "
                + "result content was identical to the valid token's. The forged tokens reuse the valid token's "
                + "subject; this shows the server accepts tokens it did not sign, which lets an attacker choose "
                + "any claims, but the scanner did not try other identities.");
        body.paragraph("Attached are the valid token's request, the malformed bearer token's refusal, then the "
                + "first forged token listed above (followed, where its forgery names a specific secret, by the "
                + "same claims signed with a random key, which was not accepted), then one request per "
                + "unvalidated claim. The no-credential refusal, the other forged tokens and the repeated refusal "
                + "controls are not attached.");
        return body.build();
    }

    private static void appendClaimProbes(IssueBodyBuilder body, List<ClaimProbe> claimProbes) {
        List<String> unvalidated = claimNames(claimProbes, true);
        List<String> validated = claimNames(claimProbes, false);
        if (!unvalidated.isEmpty()) {
            body.paragraph("A token forged the same way as the first one above was also accepted when its claims "
                    + "were changed, so the server does not validate:").findings(unvalidated);
        }
        if (!validated.isEmpty()) {
            body.paragraph("The same forged token was refused, or returned a different result, when these claims "
                    + "were invalid, so they appear to be checked:").findings(validated);
        }
    }

    private static List<String> claimNames(List<ClaimProbe> claimProbes, boolean accepted) {
        return claimProbes.stream().filter(probe -> probe.accepted() == accepted)
                .map(probe -> probe.mutation().unvalidatedClaim()).toList();
    }

    private static List<HttpRequestResponse> evidence(ForgedTokenFindings findings) {
        AcceptedForgery first = findings.firstAcceptedForgery();
        List<HttpRequestResponse> evidence = new ArrayList<>();
        evidence.add(findings.baseline());
        evidence.add(findings.malformedBearerRefusal());
        evidence.add(first.candidate());
        first.refusedWrongKeyControl().ifPresent(evidence::add);
        findings.claimProbes().stream().filter(ClaimProbe::accepted).map(ClaimProbe::exchange).forEach(evidence::add);
        return evidence;
    }

    private static String remediation() {
        return new IssueBodyBuilder()
                .paragraph("Verify every access token's signature against the authorization server's published "
                        + "keys before trusting any claim. Configure the JWT library with an explicit allow-list of "
                        + "the expected asymmetric algorithms, reject alg: none, never use a public key as an HMAC "
                        + "secret, and treat an unknown key id as a verification failure rather than resolving it "
                        + "to an empty or default key.")
                .paragraph("After the signature verifies, check that iss is the trusted authorization server, that "
                        + "aud names this MCP server, and that exp is in the future. Reject any other token with "
                        + "HTTP 401 and a WWW-Authenticate: Bearer challenge.")
                .build();
    }
}
