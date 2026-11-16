package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.LateIssueSink;
import com.mcpscanner.checks.api.RateLimitedProbing;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

public final class OutboundRequestCheck implements InsertionPointCheck, ConnectionScoped {

    private static final SkipReason NOT_FETCHABLE =
            SkipReason.notApplicable("not an MCP extension field or an OAuth fetched-URL parameter");
    private static final SkipReason COLLABORATOR_UNAVAILABLE =
            SkipReason.prerequisiteMissing("Burp Collaborator is unavailable");
    private static final SkipReason ALREADY_CONFIRMED = new SkipReason(SkipReason.Kind.ALREADY_AUDITED,
            "an outbound request from this field is already confirmed at this endpoint");
    private static final SkipReason NO_PAYLOAD = SkipReason.prerequisiteMissing("Burp Collaborator issued no payload");

    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final CollaboratorWatch watch;
    private final LateIssueSink lateIssues;
    private final FieldClassifier classifier;
    private final FieldProbes probes;
    private final OutboundRequestIssues issues = new OutboundRequestIssues(OutboundRequestDescriptor.DESCRIPTOR);
    private final AtomicReference<ConfirmedFields> confirmed = new AtomicReference<>(new ConfirmedFields());

    public OutboundRequestCheck(McpEventLog eventLog, CollaboratorWatch watch, LateIssueSink lateIssues,
                                BurpNativeJsonRpcFields burpNativeFields) {
        this.classifier = new FieldClassifier(burpNativeFields);
        this.log = new CheckLog(eventLog, OutboundRequestDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
        this.watch = watch;
        this.lateIssues = lateIssues;
        this.probes = new FieldProbes(watch);
    }

    @Override
    public CheckDescriptor descriptor() {
        return OutboundRequestDescriptor.DESCRIPTOR;
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                                  Http http) {
        String subject = SkipSubject.field(baseRequestResponse, insertionPoint);
        Optional<ProbedField> field = classifier.classify(baseRequestResponse.request(), insertionPoint);
        Optional<SkipReason> skip = skipReason(baseRequestResponse, field);
        if (skip.isPresent()) {
            notRun(subject, skip.get());
            return List.of();
        }
        return rateLimited.run(subject, http, guarded -> {
            probe(baseRequestResponse, insertionPoint, field.get(), guarded);
            return List.of();
        });
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepStrongerOfSameSubject(existingIssue, newIssue);
    }

    @Override
    public void clearConnectionState() {
        confirmed.set(new ConfirmedFields());
    }

    private void notRun(String subject, SkipReason reason) {
        if (reason == COLLABORATOR_UNAVAILABLE) {
            log.notRunOncePerLoad(subject, reason);
        } else {
            log.notRun(subject, reason);
        }
    }

    private Optional<SkipReason> skipReason(HttpRequestResponse base, Optional<ProbedField> field) {
        if (field.isEmpty()) {
            return Optional.of(NOT_FETCHABLE);
        }
        if (!watch.available()) {
            return Optional.of(COLLABORATOR_UNAVAILABLE);
        }
        if (confirmed.get().settled(FieldSubject.of(base.request(), field.get()))) {
            return Optional.of(ALREADY_CONFIRMED);
        }
        return Optional.empty();
    }

    private void probe(HttpRequestResponse base, AuditInsertionPoint insertionPoint, ProbedField field, Http http) {
        ConfirmedFields connectionFields = confirmed.get();
        List<SentProbe> sent = probes.send(insertionPoint, http);
        if (sent.size() < FieldProbes.applicable(insertionPoint).size()) {
            log.notRun(SkipSubject.field(base, insertionPoint), NO_PAYLOAD);
        }
        if (sent.isEmpty()) {
            return;
        }
        watch.watch(sent.stream().map(SentProbe::payload).toList(), new WatchedField(watch.kept(base), field,
                sent.stream().map(this::kept).toList(), connectionFields, issues, finding -> report(finding, field)));
    }

    private SentProbe kept(SentProbe probe) {
        return new SentProbe(probe.form(), probe.value(), probe.payload(), watch.kept(probe.exchange()));
    }

    private void report(OutboundFinding finding, ProbedField field) {
        log.info("reported " + finding.issue().name() + " for " + field.location());
        lateIssues.report(this, List.of(finding.issue()));
    }
}
