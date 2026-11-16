package com.mcpscanner.checks.catalog.ssrffilterbypass;

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

public final class SsrfFilterBypassCheck implements InsertionPointCheck, ConnectionScoped {

    private static final SkipReason NOT_FETCH_FIELD =
            SkipReason.notApplicable("not the URL argument of a fetch, browse or scrape operation");
    private static final SkipReason COLLABORATOR_UNAVAILABLE =
            SkipReason.prerequisiteMissing("Burp Collaborator is unavailable");
    private static final SkipReason NO_SERVER_ADDRESS =
            SkipReason.prerequisiteMissing("the Burp Collaborator server has no IPv4 address to spell");
    private static final SkipReason ALREADY_REPORTED =
            SkipReason.alreadyAudited("a filter bypass in this field is already reported at this endpoint");
    private static final SkipReason NO_PAYLOAD = SkipReason.prerequisiteMissing("Burp Collaborator issued no payload");

    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final CollaboratorWatch watch;
    private final LateIssueSink lateIssues;
    private final FetchFields fetchFields;
    private final SsrfFilterBypassIssues issues = new SsrfFilterBypassIssues(SsrfFilterBypassDescriptor.DESCRIPTOR);
    private final AtomicReference<ReportedFields> reported = new AtomicReference<>(new ReportedFields());

    public SsrfFilterBypassCheck(McpEventLog eventLog, CollaboratorWatch watch, LateIssueSink lateIssues,
                                 BurpNativeJsonRpcFields burpNativeFields) {
        this.log = new CheckLog(eventLog, SsrfFilterBypassDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
        this.watch = watch;
        this.lateIssues = lateIssues;
        this.fetchFields = new FetchFields(burpNativeFields);
    }

    @Override
    public CheckDescriptor descriptor() {
        return SsrfFilterBypassDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean requiresReply() {
        return true;
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse base, AuditInsertionPoint insertionPoint, Http http) {
        String subject = SkipSubject.field(base, insertionPoint);
        Optional<FetchField> field = fetchFields.of(base.request(), insertionPoint);
        if (field.isEmpty()) {
            log.notRun(subject, NOT_FETCH_FIELD);
            return List.of();
        }
        if (reported.get().contains(base.request(), field.get())) {
            log.notRun(subject, ALREADY_REPORTED);
            return List.of();
        }
        if (!watch.available()) {
            log.notRunOncePerLoad(subject, COLLABORATOR_UNAVAILABLE);
            return List.of();
        }
        Optional<Ipv4Literal> collaborator = watch.serverIpv4().map(Ipv4Literal::of);
        if (collaborator.isEmpty()) {
            log.notRunOncePerLoad(subject, NO_SERVER_ADDRESS);
            return List.of();
        }
        return rateLimited.run(subject, http, guarded -> {
            probe(new FieldProbe(base, insertionPoint, field.get(), guarded, subject), collaborator.get());
            return List.of();
        });
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepStrongerOfSameSubject(existingIssue, newIssue);
    }

    @Override
    public void clearConnectionState() {
        reported.set(new ReportedFields());
    }

    private void probe(FieldProbe probe, Ipv4Literal collaborator) {
        FieldSender sender = new FieldSender(probe.point(), probe.http());
        LeadSearch search = new LeadFinder(sender, probe.targetPort()).search();
        if (search.stopped().isPresent()) {
            log.notRun(probe.subject(), search.stopped().get());
            return;
        }
        if (search.leads().isEmpty()) {
            log.debug("every loopback spelling was refused for " + probe.subject());
            return;
        }
        List<ControlledLead> controlled = watch.probing(payloads ->
                ControlledLead.send(sender, collaborator, search.leads(), payloads));
        if (controlled.size() < search.leads().size()) {
            log.notRun(probe.subject(), NO_PAYLOAD);
        }
        watchControls(probe, search.refusal().orElseThrow(), controlled);
    }

    private void watchControls(FieldProbe probe, Refusal refusal, List<ControlledLead> controlled) {
        if (controlled.isEmpty()) {
            return;
        }
        TargetPage page = TargetPage.fetch(probe.http(), probe.base().request());
        ReportedFields connectionFields = reported.get();
        HttpRequestResponse base = watch.kept(probe.base());
        Refusal keptRefusal = new Refusal(kept(refusal.evidence()), refusal.signature());
        watch.watch(controlled.stream().map(ControlledLead::payload).toList(),
                new WatchedBypass(controlled.stream().map(this::kept).toList(), (proven, observed) ->
                        report(connectionFields, new BypassFinding(base, probe.field(), keptRefusal, proven,
                                observed, page))));
    }

    private ControlledLead kept(ControlledLead lead) {
        return new ControlledLead(new Lead(lead.lead().spelling(), kept(lead.lead().loopback())), lead.payload(),
                kept(lead.control()));
    }

    private SentUrl kept(SentUrl sent) {
        return sent.kept(watch.kept(sent.exchange()));
    }

    private void report(ReportedFields connectionFields, BypassFinding finding) {
        if (connectionFields.add(finding.base().request(), finding.field())) {
            log.info("reported " + SsrfFilterBypassIssues.NAME + " for " + finding.field().subject());
            lateIssues.report(this, List.of(issues.issue(finding)));
        }
    }
}
