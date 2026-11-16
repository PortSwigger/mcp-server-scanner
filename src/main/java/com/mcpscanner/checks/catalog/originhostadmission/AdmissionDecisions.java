package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

final class AdmissionDecisions {

    static final String UNREACHABLE_STREAMED_BASELINE = "the server answers with a stream "
            + "(text/event-stream) and Burp withholds streamed replies from extensions, and the scanner's own HTTP "
            + "client could not reach the server (Burp's client certificates, upstream proxy and network settings "
            + "do not apply to it). This check cannot judge it unless Burp stops treating text/event-stream as a "
            + "streaming response";

    private final CheckLog log;
    private final CredentialHeaders credentials;
    private final OriginHostAdmissionIssues issues =
            new OriginHostAdmissionIssues(OriginHostAdmissionDescriptor.DESCRIPTOR);

    AdmissionDecisions(CheckLog log, CredentialHeaders credentials) {
        this.log = log;
        this.credentials = credentials;
    }

    List<AuditIssue> decide(String test, TrialOutcome outcome, Optional<SkipReason> unprobed, String via,
                            HttpRequest exposedRequest) {
        if (outcome.baselineUnansweredOutsideBurp()) {
            log.notRun(test, SkipReason.streamedReply(UNREACHABLE_STREAMED_BASELINE));
            return List.of();
        }
        unprobed.ifPresentOrElse(reason -> log.notRun(test, reason),
                () -> log.info("decision: " + describe(outcome) + " via " + via));
        return issuesFor(outcome, TargetExposure.of(exposedRequest, credentials));
    }

    private List<AuditIssue> issuesFor(TrialOutcome outcome, TargetExposure exposure) {
        if (!outcome.conclusive()) {
            return List.of();
        }
        return Arrays.stream(AdmissionCategory.values())
                .map(category -> issues.issueFor(category, outcome, exposure))
                .flatMap(Optional::stream)
                .toList();
    }

    private static String describe(TrialOutcome outcome) {
        return outcome.status() + " " + outcome.probes().stream().map(ProbeObservation::summary)
                .collect(Collectors.joining("; ", "[", "]"));
    }
}
