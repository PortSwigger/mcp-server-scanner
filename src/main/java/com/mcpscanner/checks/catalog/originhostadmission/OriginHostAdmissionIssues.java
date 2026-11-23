package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.shared.stream.StreamEvidenceNote;

import java.util.List;
import java.util.Optional;

final class OriginHostAdmissionIssues {

    private static final String CREDENTIAL_CAVEAT = "The requests carried credentials. A browser-based attacker "
            + "would not hold them, so confirm the endpoint is reachable without credentials before treating this "
            + "as exploitable.";
    private static final String LOCAL_TARGET = "The target is a loopback or private-network address: the kind "
            + "of listener that DNS rebinding and cross-site requests from the user's browser are aimed at.";
    private static final String TLS_TARGET = "The target uses TLS. After DNS rebinding a browser would reject the "
            + "server's certificate for the attacker's name, so the rebound pair is not browser-deliverable here.";
    private static final String REMOTE_TARGET = "The target is not a loopback or private-network address. An "
            + "attacker can usually reach it directly, so header admission is a hardening concern here.";
    private static final String REMEDIATION = "Validate the Host and Origin headers on every MCP request against "
            + "an explicit allowlist and reject anything else with 403. Enable the SDK's DNS-rebinding protection "
            + "(for example Python FastMCP transport security settings or the TypeScript SDK host header "
            + "validation), bind local servers to 127.0.0.1, and require authentication.";

    private final CheckDescriptor descriptor;

    OriginHostAdmissionIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    Optional<AuditIssue> issueFor(AdmissionCategory category, TrialOutcome outcome, TargetExposure exposure) {
        List<ProbeObservation> admitted = outcome.admittedIn(category);
        if (!outcome.conclusive() || admitted.isEmpty()) {
            return Optional.empty();
        }
        AuditIssueSeverity severity = AdmissionSeverity.of(category, exposure);
        List<Evidence> evidence = evidence(outcome, admitted);
        return Optional.of(AuditIssue.auditIssue(category.issueName(),
                detail(category, admitted, outsideBurpNote(outcome, evidence), exposure),
                REMEDIATION, outcome.baseline().request().url(), severity, category.confidence(),
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null, severity, evidence.stream().map(Evidence::exchange).toList()));
    }

    private static String detail(AdmissionCategory category, List<ProbeObservation> admitted,
                                 Optional<String> outsideBurpNote, TargetExposure exposure) {
        IssueBodyBuilder body = new IssueBodyBuilder()
                .paragraph(category.lead())
                .findings(admitted.stream().map(observation -> observation.probe().label()).toList())
                .paragraph(category.probeScope())
                .paragraph(category.evidenceScope());
        outsideBurpNote.ifPresent(body::paragraph);
        body.paragraph(reachability(exposure));
        if (exposure.credentialed()) {
            body.paragraph(CREDENTIAL_CAVEAT);
        }
        return body.build();
    }

    private static String reachability(TargetExposure exposure) {
        if (!exposure.locallyReachable()) {
            return REMOTE_TARGET;
        }
        return exposure.tls() ? TLS_TARGET : LOCAL_TARGET;
    }

    private static Optional<String> outsideBurpNote(TrialOutcome outcome, List<Evidence> evidence) {
        return StreamEvidenceNote.sentOutsideBurp(evidence.stream()
                .filter(item -> outcome.wentOutsideBurp(item.exchange()))
                .map(Evidence::name)
                .toList(), evidence.size());
    }

    private static List<Evidence> evidence(TrialOutcome outcome, List<ProbeObservation> admitted) {
        ProbeObservation firstAdmitted = admitted.get(0);
        return List.of(new Evidence("the baseline request", outcome.baseline()),
                new Evidence("the " + firstAdmitted.probe().label() + " probe", firstAdmitted.exchange()));
    }

    private record Evidence(String name, HttpRequestResponse exchange) {
    }
}
