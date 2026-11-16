package com.mcpscanner.checks.registry;

import com.mcpscanner.checks.api.CheckVisitor;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.checks.shared.scancontext.ScanNotices;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;

import java.util.Objects;

public final class McpCheckAdapters implements CheckVisitor<McpCheckAdapter<?>> {

    private final ScanCheckSettings settings;
    private final McpEventLog eventLog;
    private final CheckInstrumentation instrumentation;
    private final UpstreamExchanges upstreamExchanges;
    private final ConnectionReuse connectionReuse;
    private final IssueDestination issuesBurpWouldDrop;
    private final ScanNotices auditNotices;
    private final ProbeCalls probeCalls;

    public McpCheckAdapters(ScanCheckSettings settings, McpEventLog eventLog) {
        this(settings, eventLog, CheckInstrumentation.NONE);
    }

    public McpCheckAdapters(ScanCheckSettings settings, McpEventLog eventLog, CheckInstrumentation instrumentation) {
        this(settings, eventLog, instrumentation, UpstreamExchanges.NONE);
    }

    public McpCheckAdapters(ScanCheckSettings settings, McpEventLog eventLog, CheckInstrumentation instrumentation,
                            UpstreamExchanges upstreamExchanges) {
        this(settings, eventLog, instrumentation, upstreamExchanges, ConnectionReuse.withoutLocalAnswers());
    }

    public McpCheckAdapters(ScanCheckSettings settings, McpEventLog eventLog, CheckInstrumentation instrumentation,
                            UpstreamExchanges upstreamExchanges, ConnectionReuse connectionReuse) {
        this(settings, eventLog, instrumentation, upstreamExchanges, connectionReuse, IssueDestination.NONE,
                new ScanNotices());
    }

    public McpCheckAdapters(ScanCheckSettings settings, McpEventLog eventLog, CheckInstrumentation instrumentation,
                            UpstreamExchanges upstreamExchanges, ConnectionReuse connectionReuse,
                            IssueDestination issuesBurpWouldDrop, ScanNotices auditNotices) {
        this(settings, eventLog, instrumentation, upstreamExchanges, connectionReuse, issuesBurpWouldDrop,
                auditNotices, ProbeCalls.NONE);
    }

    public McpCheckAdapters(ScanCheckSettings settings, McpEventLog eventLog, CheckInstrumentation instrumentation,
                            UpstreamExchanges upstreamExchanges, ConnectionReuse connectionReuse,
                            IssueDestination issuesBurpWouldDrop, ScanNotices auditNotices, ProbeCalls probeCalls) {
        this.probeCalls = Objects.requireNonNull(probeCalls, "probeCalls must not be null");
        this.issuesBurpWouldDrop = Objects.requireNonNull(issuesBurpWouldDrop, "issuesBurpWouldDrop must not be null");
        this.auditNotices = Objects.requireNonNull(auditNotices, "auditNotices must not be null");
        this.connectionReuse = Objects.requireNonNull(connectionReuse, "connectionReuse must not be null");
        this.upstreamExchanges = Objects.requireNonNull(upstreamExchanges, "upstreamExchanges must not be null");
        this.settings = Objects.requireNonNull(settings, "settings must not be null");
        this.eventLog = eventLog;
        this.instrumentation = instrumentation;
    }

    public McpCheckAdapter<?> adapt(McpCheck check) {
        return check.accept(this);
    }

    @Override
    public McpCheckAdapter<?> visitInsertionPointCheck(InsertionPointCheck check) {
        return new InsertionPointCheckAdapter(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse,
                issuesBurpWouldDrop, auditNotices, probeCalls);
    }

    @Override
    public McpCheckAdapter<?> visitRequestCheck(RequestCheck check) {
        return new RequestCheckAdapter(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse,
                issuesBurpWouldDrop, auditNotices, probeCalls);
    }

    @Override
    public McpCheckAdapter<?> visitHostCheck(HostCheck check) {
        return new HostCheckAdapter(settings, eventLog, check, instrumentation, upstreamExchanges, connectionReuse,
                issuesBurpWouldDrop, auditNotices, probeCalls);
    }
}
