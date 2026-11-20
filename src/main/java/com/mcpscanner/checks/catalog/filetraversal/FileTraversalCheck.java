package com.mcpscanner.checks.catalog.filetraversal;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.RateLimitedProbing;
import com.mcpscanner.checks.api.RateLimitedSends;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.checks.shared.field.InsertionPointNames;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestKind;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class FileTraversalCheck implements InsertionPointCheck {

    private static final SkipReason NOT_MCP = SkipReason.notApplicable("not an MCP request");

    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final Supplier<String> missingNames;
    private final Supplier<Optional<HttpService>> probeService;
    private final InsertionPointNames insertionPointNames;
    private final FindingClassifier classifier = new FindingClassifier();
    private final FileTraversalIssues issues = new FileTraversalIssues(FileTraversalDescriptor.DESCRIPTOR);

    public FileTraversalCheck(Supplier<String> missingNames, Supplier<Optional<HttpService>> probeService,
                              BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog) {
        this.log = new CheckLog(eventLog, FileTraversalDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
        this.missingNames = missingNames;
        this.probeService = probeService;
        this.insertionPointNames = new InsertionPointNames(burpNativeFields);
    }

    @Override
    public CheckDescriptor descriptor() {
        return FileTraversalDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean requiresReply() {
        return true;
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint, Http http) {
        String subject = SkipSubject.field(baseRequestResponse, insertionPoint);
        if (McpRequestDetector.classify(baseRequestResponse) == McpRequestKind.NOT_MCP) {
            log.notRun(subject, NOT_MCP);
            return List.of();
        }
        return rateLimited.run(subject, http, sends -> probe(baseRequestResponse, insertionPoint, sends));
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepExistingWhen(IssueIdentity.sameSubject(existingIssue, newIssue));
    }

    private List<AuditIssue> probe(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                                   RateLimitedSends sends) {
        String missingName = missingNames.get();
        PayloadSender prober = new PayloadSender(sends.probes(), insertionPoint, probeService);
        PayloadSender confirmer = new PayloadSender(sends.confirmations(), insertionPoint, probeService);
        List<Finding> findings = new ArrayList<>(classifier.classify(new ContentProbe(prober, confirmer)
                .run(TraversalPayloads.forBaseValue(insertionPoint.baseValue()), missingName)));
        new RootBoundaryProbe(prober).run(missingName).ifPresent(findings::add);
        String fieldName = insertionPointNames.nameOf(baseRequestResponse.request(), insertionPoint);
        return findings.stream()
                .map(finding -> issues.issueFor(finding, baseRequestResponse.request(), fieldName))
                .toList();
    }
}
