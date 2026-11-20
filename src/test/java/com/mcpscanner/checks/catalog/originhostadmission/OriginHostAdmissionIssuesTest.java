package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OriginHostAdmissionIssuesTest {

    private final OriginHostAdmissionIssues issues =
            new OriginHostAdmissionIssues(OriginHostAdmissionDescriptor.DESCRIPTOR);
    private HttpRequestResponse exchange;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        exchange = AdmissionServers.captured(AdmissionServers.toolsList(AdmissionServers.LOOPBACK_URL));
    }

    @Test
    void namesEveryAdmittedProbeAndBoundsTheClaimToHeaderAdmission() {
        AuditIssue issue = issues.issueFor(AdmissionCategory.ORIGIN, outcome(TrialOutcome.TrialStatus.CONCLUSIVE),
                new TargetExposure(true, false, false)).orElseThrow();

        assertThat(issue.detail()).contains("Origin: http://evil.example", "Origin: null")
                .contains("proves header admission only").doesNotContain("credentials");
    }

    @Test
    void warnsWhenTheRequestsCarriedCredentials() {
        AuditIssue issue = issues.issueFor(AdmissionCategory.ORIGIN, outcome(TrialOutcome.TrialStatus.CONCLUSIVE),
                new TargetExposure(true, true, false)).orElseThrow();

        assertThat(issue.detail()).contains("The requests carried credentials");
    }

    @Test
    void explainsThatARemoteTargetIsAHardeningConcern() {
        AuditIssue issue = issues.issueFor(AdmissionCategory.ORIGIN, outcome(TrialOutcome.TrialStatus.CONCLUSIVE),
                new TargetExposure(false, false, false)).orElseThrow();

        assertThat(issue.detail()).contains("hardening concern");
    }

    @Test
    void reportsNothingForACategoryWithoutAnAdmittedProbe() {
        assertThat(issues.issueFor(AdmissionCategory.HOST, outcome(TrialOutcome.TrialStatus.CONCLUSIVE),
                new TargetExposure(true, false, false))).isEmpty();
    }

    @Test
    void reportsNothingForAnInconclusiveTrial() {
        assertThat(issues.issueFor(AdmissionCategory.ORIGIN, outcome(TrialOutcome.TrialStatus.CONTROL_DIVERGED),
                new TargetExposure(true, false, false))).isEmpty();
    }

    private TrialOutcome outcome(TrialOutcome.TrialStatus status) {
        List<ProbeObservation> probes = List.of(
                new ProbeObservation(AdmissionProbe.STANDARD_SET.get(0), exchange, ProbeVerdict.ADMITTED),
                new ProbeObservation(AdmissionProbe.STANDARD_SET.get(1), exchange, ProbeVerdict.ADMITTED),
                new ProbeObservation(AdmissionProbe.STANDARD_SET.get(2), exchange, ProbeVerdict.REFUSED),
                new ProbeObservation(AdmissionProbe.STANDARD_SET.get(3), exchange, ProbeVerdict.INCONCLUSIVE));
        return new TrialOutcome(status, exchange, probes);
    }
}
