package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.ImplementedKind;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.checks.api.ReplyRequirement;
import com.mcpscanner.checks.api.RetryAfterHonouringHttp;
import com.mcpscanner.checks.api.RetryAfterWaits;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.shared.scancontext.CurrentInvocation;
import com.mcpscanner.checks.shared.scancontext.CurrentScan;
import com.mcpscanner.checks.shared.scancontext.ScanContext;
import com.mcpscanner.checks.shared.scancontext.ScanNotices;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.ConnectionReusingHttp;
import com.mcpscanner.http.CountingHttp;
import com.mcpscanner.http.RequestTally;
import com.mcpscanner.http.ExchangeLease;
import com.mcpscanner.http.RetainingHttp;
import com.mcpscanner.http.UpstreamEvidence;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.Counted;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

public abstract class McpCheckAdapter<C extends McpCheck> implements ActiveScanCheck, ManagedCheck, ConnectionScoped {

    private static final String RESENT_OUTSIDE_BURP = "Burp refused a streamed reply, so probes were sent again outside"
            + " Burp; a probe Burp had already put on the wire reached the server twice";
    private static final String MISSING_REPLY = "Burp gave the extension no reply: it withholds streamed replies,"
            + " and a timeout or dropped connection looks the same";

    private final ScanCheckSettings settings;
    private final McpEventLog eventLog;
    private final C check;
    private final CheckInstrumentation instrumentation;
    private final UpstreamEvidence upstreamEvidence;
    private final ConnectionReuse connectionReuse;
    private final IssueDestination issuesBurpWouldDrop;
    private final CheckLog log;
    private final ScanNotices auditNotices;
    private final ProbeCalls probeCalls;

    protected McpCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, C check) {
        this(settings, eventLog, check, CheckInstrumentation.NONE);
    }

    protected McpCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, C check,
                              CheckInstrumentation instrumentation) {
        this(settings, eventLog, check, instrumentation, UpstreamExchanges.NONE);
    }

    protected McpCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, C check,
                              CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges) {
        this(settings, eventLog, check, instrumentation, upstreamExchanges, ConnectionReuse.withoutLocalAnswers());
    }

    protected McpCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, C check,
                              CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                              ConnectionReuse connectionReuse) {
        this(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse, IssueDestination.NONE,
                new ScanNotices());
    }

    protected McpCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, C check,
                              CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                              ConnectionReuse connectionReuse, IssueDestination issuesBurpWouldDrop,
                              ScanNotices auditNotices) {
        this(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse, issuesBurpWouldDrop,
                auditNotices, ProbeCalls.NONE);
    }

    protected McpCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, C check,
                              CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                              ConnectionReuse connectionReuse, IssueDestination issuesBurpWouldDrop,
                              ScanNotices auditNotices, ProbeCalls probeCalls) {
        this.probeCalls = Objects.requireNonNull(probeCalls, "probeCalls must not be null");
        this.issuesBurpWouldDrop = Objects.requireNonNull(issuesBurpWouldDrop, "issuesBurpWouldDrop must not be null");
        this.auditNotices = Objects.requireNonNull(auditNotices, "auditNotices must not be null");
        this.connectionReuse = Objects.requireNonNull(connectionReuse, "connectionReuse must not be null");
        this.upstreamEvidence = new UpstreamEvidence(upstreamExchanges);
        this.instrumentation = Objects.requireNonNull(instrumentation, "instrumentation must not be null");
        this.settings = Objects.requireNonNull(settings, "settings must not be null");
        this.eventLog = eventLog;
        this.check = Objects.requireNonNull(check, "check must not be null");
        ImplementedKind.requireDeclaredKindMatches(check);
        this.log = new CheckLog(eventLog == null ? McpEventLog.noop() : eventLog, check.descriptor().id());
    }

    protected final CheckLog log() {
        return log;
    }

    protected final C check() {
        return check;
    }

    @Override
    public final CheckDescriptor descriptor() {
        return check.descriptor();
    }

    @Override
    public final void registerWith(ActiveCheckRegistrar registrar) {
        registrar.register(this, descriptor().kind().scanCheckType());
    }

    @Override
    public final String checkName() {
        return descriptor().issueName();
    }

    @Override
    public final AuditResult doCheck(HttpRequestResponse baseRequestResponse,
                                     AuditInsertionPoint insertionPoint,
                                     Http http) {
        return CurrentScan.noticing(auditNotices, () -> audit(baseRequestResponse, insertionPoint, http));
    }

    public final void invocationsSkipped(int invocations, SkipReason reason) {
        log.notRun(Counted.of(invocations, "invocation"), reason);
    }

    private AuditResult audit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                              Http http) {
        return loggingFailures(() -> watchedHttpFor(baseRequestResponse, insertionPoint, http))
                .map(watch -> run(baseRequestResponse, insertionPoint, watch))
                .orElseGet(() -> AuditResult.auditResult(List.of()));
    }

    private Optional<StreamingRefusalWatch> watchedHttpFor(HttpRequestResponse baseRequestResponse,
                                                           AuditInsertionPoint insertionPoint, Http http) {
        Optional<SkipReason> skip = skipReason(baseRequestResponse, insertionPoint);
        if (skip.isPresent()) {
            log.notRun(SkipSubject.of(baseRequestResponse), skip.get());
            return Optional.empty();
        }
        noteMissingReply(baseRequestResponse);
        return Optional.of(new StreamingRefusalWatch(ConnectionReusingHttp.around(http, connectionReuse)));
    }

    private void noteMissingReply(HttpRequestResponse baseRequestResponse) {
        if (baseRequestResponse.request() != null && baseRequestResponse.response() == null) {
            log.firstAtInfo(CurrentScan::firstNotice, MISSING_REPLY, "auditing "
                    + SkipSubject.of(baseRequestResponse) + " without its reply (" + MISSING_REPLY + ")");
        }
    }

    private AuditResult run(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                            StreamingRefusalWatch watch) {
        try (ExchangeLease lease = upstreamEvidence.retaining()) {
            lease.hold(baseRequestResponse);
            List<AuditIssue> issues = CurrentInvocation.holding(lease, () ->
                    reportable(runUnderLease(baseRequestResponse, insertionPoint, watch, lease)));
            instrumentation.reported(descriptor().id(), issues);
            warnIfProbesWereResent(watch);
            return AuditResult.auditResult(issuesToReturnToBurp(issues, watch));
        }
    }

    private List<AuditIssue> runUnderLease(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                                           StreamingRefusalWatch watch, ExchangeLease lease) {
        String checkId = descriptor().id();
        AuditResult result = ScanCheckLogging.runAndLog(eventLog, checkId, requests -> runApplicableCheck(
                baseRequestResponse, insertionPoint, probeHttp(checkId, watch, requests, lease)));
        return upstreamEvidence.translate(result.auditIssues());
    }

    private List<AuditIssue> reportable(List<AuditIssue> translated) {
        SentinelFreeEvidence.noteStillProxied(translated, log);
        return SentinelFreeEvidence.of(translated);
    }

    private void warnIfProbesWereResent(StreamingRefusalWatch watch) {
        if (watch.sawRefusal() && CurrentScan.firstNotice(CheckLog.prefix(descriptor().id()) + RESENT_OUTSIDE_BURP)) {
            log.warn(RESENT_OUTSIDE_BURP);
        }
    }

    private <T> T loggingFailures(Supplier<T> step) {
        try {
            return step.get();
        } catch (RuntimeException failure) {
            ScanCheckLogging.logError(eventLog, descriptor().id(), failure);
            throw failure;
        }
    }

    private List<AuditIssue> issuesToReturnToBurp(List<AuditIssue> issues, StreamingRefusalWatch watch) {
        if (!watch.sawRefusal() || issues.isEmpty()) {
            return issues;
        }
        issuesBurpWouldDrop.add(this, issues, CurrentScan.get());
        ScanCheckLogging.logIssuesAddedToSiteMapDirectly(eventLog, descriptor().id(), issues.size());
        return List.of();
    }

    private Http probeHttp(String checkId, Http http, RequestTally requests, ExchangeLease lease) {
        return instrumentation.probeHttp(checkId, new RetainingHttp(new RetryAfterHonouringHttp(
                CountingHttp.counting(http, requests), log, CurrentScan::firstNotice,
                RetryAfterWaits.onThisThreadOnly(scanStillRunning(CurrentScan.get()))), lease));
    }

    private static BooleanSupplier scanStillRunning(Optional<ScanContext> scan) {
        return () -> scan.map(context -> !context.cancelled()).orElse(true);
    }

    public final List<AuditIssue> lateIssues(List<AuditIssue> issues) {
        String checkId = descriptor().id();
        List<AuditIssue> translated = reportable(upstreamEvidence.translate(issues));
        ScanCheckLogging.logLateIssues(eventLog, checkId, translated.size());
        instrumentation.reported(checkId, translated);
        return translated;
    }

    boolean runs(McpCheck candidate) {
        return check == candidate;
    }

    @Override
    public final ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return check.consolidate(existingIssue, newIssue);
    }

    @Override
    public void clearConnectionState() {
        auditNotices.forget();
        if (check instanceof ConnectionScoped scoped) {
            scoped.clearConnectionState();
        }
    }

    protected abstract AuditResult runApplicableCheck(HttpRequestResponse baseRequestResponse,
                                                      AuditInsertionPoint insertionPoint,
                                                      Http http);

    protected Optional<SkipReason> claim(HttpRequestResponse baseRequestResponse) {
        return Optional.empty();
    }

    private Optional<SkipReason> skipReason(HttpRequestResponse baseRequestResponse,
                                            AuditInsertionPoint insertionPoint) {
        if (!isEnabled()) {
            return Optional.of(SkipReason.disabled());
        }
        if (!ReplyRequirement.permits(check, baseRequestResponse)) {
            return Optional.of(SkipReason.notification());
        }
        if (runsOncePerCall() && probeCalls.include(baseRequestResponse)) {
            return Optional.of(SkipReason.notApplicable("a probe call repeats its base call; checked there"));
        }
        if (!runsOncePerCall() && probeCalls.include(baseRequestResponse)
                && !probeCalls.fuzzesAddedLeaf(baseRequestResponse, insertionPoint)) {
            return Optional.of(SkipReason.notApplicable("a probe call fuzzes only the argument it added; the rest"
                    + " is fuzzed on its base call"));
        }
        return claim(baseRequestResponse);
    }

    private boolean runsOncePerCall() {
        return descriptor().kind() != CheckKind.INSERTION_POINT;
    }

    private boolean isEnabled() {
        CheckDescriptor descriptor = descriptor();
        return settings.isEnabled(descriptor.id(), descriptor.defaultEnabled());
    }
}
