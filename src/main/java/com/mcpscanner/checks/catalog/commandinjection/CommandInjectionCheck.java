package com.mcpscanner.checks.catalog.commandinjection;

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
import com.mcpscanner.checks.shared.field.InsertionPointNames;
import com.mcpscanner.checks.shared.session.StreamingFallback;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.List;

public final class CommandInjectionCheck implements InsertionPointCheck, ConnectionScoped {

    private static final SkipReason NOT_MCP = SkipReason.notApplicable("not an MCP request");
    private static final SkipReason UNREPLIED_BASELINE =
            SkipReason.prerequisiteMissing("the baseline got no JSON-RPC reply");
    private static final SkipReason CANARY_IN_BASELINE =
            SkipReason.notApplicable("the baseline already contains the canary result");
    private static final SkipReason UNRESPONSIVE = SkipReason.transportFailure(
            ProbeField.UNANSWERED_PROBES_BEFORE_GIVING_UP + " consecutive probes got no response");

    private final StreamingFallback streamedReplies = StreamingFallback.outsideBurp();
    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final CanarySource canaries;
    private final InBandShellProbe shell;
    private final GenericEvaluatorProbe evaluators;
    private final OptionInjectionProbe options = new OptionInjectionProbe();
    private final OutOfBandShellProbe outOfBand;
    private final LateIssueSink lateIssues;
    private final InsertionPointNames insertionPointNames;
    private final CommandInjectionIssues issues = new CommandInjectionIssues(
            CommandInjectionDescriptor.DESCRIPTOR.issueBackground(), CommandInjectionDescriptor.DESCRIPTOR.cwes(),
            CommandInjectionDescriptor.DESCRIPTOR.references());

    public CommandInjectionCheck(CollaboratorWatch watch, LateIssueSink lateIssues,
                                 BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog) {
        this(CanarySource.random(), watch, lateIssues, burpNativeFields, eventLog);
    }

    CommandInjectionCheck(CanarySource canaries, CollaboratorWatch watch, LateIssueSink lateIssues,
                          BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog) {
        this.log = new CheckLog(eventLog, CommandInjectionDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
        this.canaries = canaries;
        this.shell = new InBandShellProbe(canaries);
        this.evaluators = new GenericEvaluatorProbe(canaries);
        this.outOfBand = new OutOfBandShellProbe(watch, log);
        this.lateIssues = lateIssues;
        this.insertionPointNames = new InsertionPointNames(burpNativeFields);
    }

    @Override
    public void clearConnectionState() {
        streamedReplies.forgetStreamedRoutes();
    }

    @Override
    public CheckDescriptor descriptor() {
        return CommandInjectionDescriptor.DESCRIPTOR;
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                                  Http http) {
        String subject = SkipSubject.field(baseRequestResponse, insertionPoint);
        if (!McpRequestDetector.classify(baseRequestResponse).isMcp()) {
            log.notRun(subject, NOT_MCP);
            return List.of();
        }
        return rateLimited.run(subject, streamedReplies.around(http),
                guarded -> probe(new ProbeField(baseRequestResponse, insertionPoint,
                        insertionPointNames.nameOf(baseRequestResponse.request(), insertionPoint), guarded)));
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepExistingWhen(IssueIdentity.sameSubject(existingIssue, newIssue));
    }

    private List<AuditIssue> probe(ProbeField field) {
        List<AuditIssue> found = findings(field);
        if (field.unresponsive()) {
            log.notRun(field.described(), UNRESPONSIVE);
        }
        return found;
    }

    private List<AuditIssue> findings(ProbeField field) {
        ProbeOutcome inBand = probeInBand(field);
        if (inBand.conclusive()) {
            return inBand.finding().map(issues::render).stream().toList();
        }
        outOfBand.probe(field, this::reportLate);
        return List.of();
    }

    private void reportLate(Finding finding) {
        lateIssues.report(this, List.of(issues.render(finding)));
    }

    private ProbeOutcome probeInBand(ProbeField field) {
        InjectionReply baseline = field.baseline();
        ArithmeticCanary canary = canaries.next();
        if (!baseline.answered()) {
            return skipInBand(field, UNREPLIED_BASELINE);
        }
        if (baseline.contains(canary.result())) {
            return skipInBand(field, CANARY_IN_BASELINE);
        }
        ProbeOutcome shellResult = shell.probe(field, baseline, canary);
        if (shellResult.conclusive()) {
            return shellResult;
        }
        ProbeOutcome evaluated = evaluators.probe(field, baseline, canary);
        return evaluated.conclusive() ? evaluated : options.probe(field, baseline);
    }

    private ProbeOutcome skipInBand(ProbeField field, SkipReason reason) {
        log.notRun("the in-band probes of " + field.described(), reason);
        return ProbeOutcome.inconclusive();
    }
}
