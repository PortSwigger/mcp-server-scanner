package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.HttpService;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.RetryingHostCheck;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.checks.shared.session.StreamingFallback;
import com.mcpscanner.checks.shared.stream.EventStreams;
import com.mcpscanner.checks.shared.stream.JdkStreamOpener;
import com.mcpscanner.checks.shared.stream.StreamOpener;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.SseProbeStreams;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class OriginHostAdmissionCheck implements RetryingHostCheck, ConnectionScoped {

    private final List<HostTrial> trials;
    private final StreamingFallback streamedReplies = StreamingFallback.outsideBurp();

    public OriginHostAdmissionCheck(McpEventLog eventLog, CredentialHeaders credentials,
                                    Supplier<Optional<HttpService>> streamProxy, EventStreams streams,
                                    ProbeSessions probeSessions) {
        this(eventLog, credentials, streamProxy, streams, probeSessions, Optional::empty,
                new JdkStreamOpener(eventLog));
    }

    public OriginHostAdmissionCheck(McpEventLog eventLog, CredentialHeaders credentials,
                                    Supplier<Optional<HttpService>> streamProxy, EventStreams streams,
                                    ProbeSessions probeSessions, Supplier<Optional<SseProbeStreams>> sseStreams,
                                    StreamOpener streamOpener) {
        CheckLog log = new CheckLog(eventLog, OriginHostAdmissionDescriptor.DESCRIPTOR.id());
        AdmissionDecisions decisions = new AdmissionDecisions(log, credentials);
        CapturedSessionReplay replay = new CapturedSessionReplay(new FreshProbeSession(probeSessions, log));
        this.trials = List.of(
                new RequestAdmissionHostTrial(decisions, credentials, streamedReplies, streamProxy, replay),
                new StreamAdmissionHostTrial(log, decisions, credentials, streamProxy, streams),
                new CorsPreflightHostTrial(streamProxy,
                        new PreflightCorsRead(log, credentials, streamedReplies, replay),
                        new StreamCorsRead(log, sseStreams, streamOpener)));
    }

    @Override
    public CheckDescriptor descriptor() {
        return OriginHostAdmissionDescriptor.DESCRIPTOR;
    }

    @Override
    public List<HostTrial> trials() {
        return trials;
    }

    @Override
    public void clearConnectionState() {
        streamedReplies.forgetStreamedRoutes();
    }
}
