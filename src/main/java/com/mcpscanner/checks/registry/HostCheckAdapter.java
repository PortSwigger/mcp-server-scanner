package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.api.HostAudits;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.scancontext.ScanNotices;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;

import java.util.Optional;

public final class HostCheckAdapter extends McpCheckAdapter<HostCheck> {

    private final HostAudits hostAudits;

    public HostCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, HostCheck check) {
        this(settings, eventLog, check, CheckInstrumentation.NONE);
    }

    public HostCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, HostCheck check,
            CheckInstrumentation instrumentation) {
        this(settings, eventLog, check, instrumentation, UpstreamExchanges.NONE);
    }

    public HostCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, HostCheck check,
            CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges) {
        this(settings, eventLog, check, instrumentation, upstreamExchanges, ConnectionReuse.withoutLocalAnswers());
    }

    public HostCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, HostCheck check,
                CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                ConnectionReuse connectionReuse) {
        this(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse, IssueDestination.NONE,
                new ScanNotices());
    }

    public HostCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, HostCheck check,
                CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                ConnectionReuse connectionReuse, IssueDestination issuesBurpWouldDrop, ScanNotices auditNotices) {
        this(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse, issuesBurpWouldDrop,
                auditNotices, ProbeCalls.NONE);
    }

    public HostCheckAdapter(ScanCheckSettings settings, McpEventLog eventLog, HostCheck check,
                CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                ConnectionReuse connectionReuse, IssueDestination issuesBurpWouldDrop, ScanNotices auditNotices, ProbeCalls probeCalls) {
        super(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse, issuesBurpWouldDrop,
                auditNotices, probeCalls);
        this.hostAudits = new HostAudits(check, log());
    }

    @Override
    protected Optional<SkipReason> claim(HttpRequestResponse baseRequestResponse) {
        return hostAudits.whyNotApplicable(baseRequestResponse);
    }

    @Override
    protected AuditResult runApplicableCheck(HttpRequestResponse baseRequestResponse,
                                             AuditInsertionPoint insertionPoint,
                                             Http http) {
        return AuditResult.auditResult(hostAudits.audit(baseRequestResponse, http));
    }

    @Override
    public void clearConnectionState() {
        hostAudits.clear();
        super.clearConnectionState();
    }
}
