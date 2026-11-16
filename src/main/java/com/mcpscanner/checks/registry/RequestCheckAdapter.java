package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.checks.shared.scancontext.ScanNotices;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;

public final class RequestCheckAdapter extends McpCheckAdapter<RequestCheck> {

    public RequestCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, RequestCheck check) {
        this(settings, eventLog, check, CheckInstrumentation.NONE);
    }

    public RequestCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, RequestCheck check,
            CheckInstrumentation instrumentation) {
        this(settings, eventLog, check, instrumentation, UpstreamExchanges.NONE);
    }

    public RequestCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, RequestCheck check,
            CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges) {
        this(settings, eventLog, check, instrumentation, upstreamExchanges, ConnectionReuse.withoutLocalAnswers());
    }

    public RequestCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, RequestCheck check,
                CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                ConnectionReuse connectionReuse) {
        this(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse, IssueDestination.NONE,
                new ScanNotices());
    }

    public RequestCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, RequestCheck check,
                CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                ConnectionReuse connectionReuse, IssueDestination issuesBurpWouldDrop, ScanNotices auditNotices) {
        this(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse, issuesBurpWouldDrop,
                auditNotices, ProbeCalls.NONE);
    }

    public RequestCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, RequestCheck check,
                CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                ConnectionReuse connectionReuse, IssueDestination issuesBurpWouldDrop, ScanNotices auditNotices, ProbeCalls probeCalls) {
        super(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse, issuesBurpWouldDrop,
                auditNotices, probeCalls);
    }

    @Override
    protected AuditResult runApplicableCheck(HttpRequestResponse baseRequestResponse,
                                             AuditInsertionPoint insertionPoint,
                                             Http http) {
        return AuditResult.auditResult(check().audit(baseRequestResponse, http));
    }
}
