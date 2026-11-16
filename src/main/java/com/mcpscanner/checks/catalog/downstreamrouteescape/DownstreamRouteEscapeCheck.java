package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.RateLimitedProbing;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.Optional;

public final class DownstreamRouteEscapeCheck implements InsertionPointCheck {

    private static final SkipReason PROTOCOL_METADATA =
            SkipReason.notApplicable("protocol metadata field, not a call argument");
    private static final SkipReason NOT_A_CALL =
            SkipReason.notApplicable("not a tools/call, prompts/get or resources/read");
    private static final SkipReason NO_REPLY = SkipReason.prerequisiteMissing("the server gave no reply to the base call");

    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final ReplySignature signatures = new ReplySignature(new PayloadMask());
    private final CallRequests calls = new CallRequests();
    private final RouteDifferential differential = new RouteDifferential(signatures, new RejectionWording());
    private final DownstreamRouteEscapeIssues issues =
            new DownstreamRouteEscapeIssues(DownstreamRouteEscapeDescriptor.DESCRIPTOR);
    private final List<RouteProbe> probes = RouteProbeCatalog.standard();

    public DownstreamRouteEscapeCheck(McpEventLog eventLog) {
        this.log = new CheckLog(eventLog, DownstreamRouteEscapeDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
    }

    @Override
    public CheckDescriptor descriptor() {
        return DownstreamRouteEscapeDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean requiresReply() {
        return true;
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                                  Http http) {
        String subject = SkipSubject.field(baseRequestResponse, insertionPoint);
        Optional<SkipReason> skip = skipReason(baseRequestResponse, insertionPoint);
        if (skip.isPresent()) {
            log.notRun(subject, skip.get());
            return List.of();
        }
        return rateLimited.run(subject, http, guarded -> probe(baseRequestResponse, insertionPoint, guarded));
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepExistingWhen(IssueIdentity.sameDetail(existingIssue, newIssue));
    }

    private Optional<SkipReason> skipReason(HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        if (ProtocolMetadataField.is(insertionPoint)) {
            return Optional.of(PROTOCOL_METADATA);
        }
        if (!calls.isCall(base)) {
            return Optional.of(NOT_A_CALL);
        }
        if (!calls.answered(base)) {
            return Optional.of(NO_REPLY);
        }
        return Optional.empty();
    }

    private List<AuditIssue> probe(HttpRequestResponse base, AuditInsertionPoint insertionPoint, Http http) {
        ValueSender sender = value -> http.sendRequest(
                insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(value)));
        return firstDifference(sender)
                .map(difference -> List.of(issues.issueFor(base, insertionPoint, difference)))
                .orElse(List.of());
    }

    private Optional<RouteDifference> firstDifference(ValueSender sender) {
        for (RouteProbe probe : probes) {
            Optional<RouteDifference> difference = differential.run(probe, sender);
            if (difference.isPresent()) {
                return difference;
            }
        }
        return Optional.empty();
    }
}
