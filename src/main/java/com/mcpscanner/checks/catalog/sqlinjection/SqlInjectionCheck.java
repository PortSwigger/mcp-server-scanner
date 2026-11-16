package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.RateLimitedProbing;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.checks.shared.field.InsertionPointNames;
import com.mcpscanner.checks.shared.session.StreamingFallback;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.List;
import java.util.Optional;

public final class SqlInjectionCheck implements InsertionPointCheck, ConnectionScoped {

    private static final SkipReason NOT_MCP = SkipReason.notApplicable("not an MCP request");
    private static final SkipReason UNREPLIED_BASELINE =
            SkipReason.prerequisiteMissing("the baseline got no JSON-RPC reply");
    private static final SkipReason RUNS_WHOLE_STATEMENTS =
            SkipReason.notApplicable("the field runs whole SQL statements by design");
    private static final SkipReason UNSTABLE_BASELINE = SkipReason.notApplicable(
            "the reply did not reproduce: the baseline resent or the repeated rewrites disagreed");
    private static final SkipReason UNRESPONSIVE = SkipReason.transportFailure(
            ProbeField.UNANSWERED_PROBES_BEFORE_GIVING_UP + " consecutive probes got no response");

    private final StreamingFallback streamedReplies = StreamingFallback.outsideBurp();
    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final InsertionPointNames insertionPointNames;
    private final EquivalenceProbe equivalence;
    private final Confirmation confirmation;
    private final SqlInjectionIssues issues = new SqlInjectionIssues(SqlInjectionDescriptor.DESCRIPTOR);

    public SqlInjectionCheck(BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog) {
        this(new Canaries(), burpNativeFields, eventLog);
    }

    SqlInjectionCheck(Canaries canaries, BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog) {
        this.log = new CheckLog(eventLog, SqlInjectionDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
        this.insertionPointNames = new InsertionPointNames(burpNativeFields);
        this.equivalence = new EquivalenceProbe(canaries);
        this.confirmation = new Confirmation(equivalence, new StatementControl(canaries));
    }

    @Override
    public void clearConnectionState() {
        streamedReplies.forgetStreamedRoutes();
    }

    @Override
    public CheckDescriptor descriptor() {
        return SqlInjectionDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean requiresReply() {
        return true;
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                                  Http http) {
        String subject = SkipSubject.field(baseRequestResponse, insertionPoint);
        if (!McpRequestDetector.classify(baseRequestResponse).isMcp()) {
            log.notRun(subject, NOT_MCP);
            return List.of();
        }
        return rateLimited.run(subject, streamedReplies.around(http), guarded -> {
            ProbeField field = new ProbeField(baseRequestResponse, insertionPoint, guarded);
            return probe(field).map(finding -> issues.render(finding, baseRequestResponse.request(),
                    insertionPointNames.nameOf(baseRequestResponse.request(), insertionPoint))).stream().toList();
        });
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepExistingWhen(IssueIdentity.sameSubject(existingIssue, newIssue));
    }

    private Optional<Finding> probe(ProbeField field) {
        Probe baseline = field.baseline();
        if (!baseline.shape().answered()) {
            log.notRun(field.described(), UNREPLIED_BASELINE);
            return Optional.empty();
        }
        for (ValueSlot slot : ValueSlots.of(field.original())) {
            SlotSurvey survey = equivalence.survey(field, slot, baseline);
            Optional<Verdict> verdict = survey.sqlSpecific().map(found -> confirmation.confirm(field, survey, baseline));
            if (field.gaveUp()) {
                logUnresponsive(field);
                return Optional.empty();
            }
            Optional<Verdict.Outcome> outcome = verdict.map(Verdict::outcome);
            if (outcome.filter(Verdict.Outcome.BY_DESIGN::equals).isPresent()) {
                log.notRun(field.described(), RUNS_WHOLE_STATEMENTS);
                return Optional.empty();
            }
            if (outcome.filter(Verdict.Outcome.UNSTABLE::equals).isPresent()) {
                log.notRun(field.described(), UNSTABLE_BASELINE);
                return Optional.empty();
            }
            Optional<Finding> finding = verdict.flatMap(Verdict::finding);
            if (finding.isPresent()) {
                return finding;
            }
        }
        return Optional.empty();
    }

    private void logUnresponsive(ProbeField field) {
        if (field.unresponsive()) {
            log.notRun(field.described(), UNRESPONSIVE);
        }
    }
}
