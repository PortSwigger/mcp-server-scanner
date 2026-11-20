package com.mcpscanner.checks.api;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.http.HttpService;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.mcp.SseProbeStreams;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

public record CheckServices(
        McpEventLog eventLog,
        Supplier<AuthStrategy> authStrategy,
        CollaboratorWatch collaboratorWatch,
        Supplier<Optional<HttpService>> probeService,
        Supplier<PrincipalRoster> principals,
        AccessLedger accessLedger,
        PrincipalListings principalListings,
        Supplier<Optional<SseProbeStreams>> sseProbeStreams,
        LateIssueSink lateIssues,
        BurpNativeJsonRpcFields burpNativeFields,
        SignedInConsent signedInConsent
) {
    public CheckServices(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy,
                         CollaboratorWatch collaboratorWatch, Supplier<Optional<HttpService>> probeService,
                         Supplier<PrincipalRoster> principals, AccessLedger accessLedger,
                         PrincipalListings principalListings, Supplier<Optional<SseProbeStreams>> sseProbeStreams,
                         LateIssueSink lateIssues, BurpNativeJsonRpcFields burpNativeFields) {
        this(eventLog, authStrategy, collaboratorWatch, probeService, principals, accessLedger, principalListings,
                sseProbeStreams, lateIssues, burpNativeFields, SignedInConsent.OPTED_OUT);
    }

    public CheckServices(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy,
                         Supplier<Optional<CollaboratorClient>> collaborator,
                         Supplier<Optional<HttpService>> probeService, Supplier<PrincipalRoster> principals,
                         AccessLedger accessLedger, PrincipalListings principalListings) {
        this(eventLog, authStrategy, collaborator, probeService, principals, accessLedger, principalListings,
                Optional::empty);
    }

    public CheckServices(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy,
                         Supplier<Optional<CollaboratorClient>> collaborator,
                         Supplier<Optional<HttpService>> probeService, Supplier<PrincipalRoster> principals,
                         AccessLedger accessLedger, PrincipalListings principalListings,
                         Supplier<Optional<SseProbeStreams>> sseProbeStreams) {
        this(eventLog, authStrategy, new CollaboratorWatch(collaborator, eventLog), probeService, principals,
                accessLedger, principalListings, sseProbeStreams, LateIssueSink.DISCARD, BurpNativeJsonRpcFields.ABSENT);
    }

    public CheckServices {
        Objects.requireNonNull(eventLog, "eventLog must not be null");
        Objects.requireNonNull(authStrategy, "authStrategy must not be null");
        Objects.requireNonNull(collaboratorWatch, "collaboratorWatch must not be null");
        Objects.requireNonNull(probeService, "probeService must not be null");
        Objects.requireNonNull(principals, "principals must not be null");
        Objects.requireNonNull(accessLedger, "accessLedger must not be null");
        Objects.requireNonNull(principalListings, "principalListings must not be null");
        Objects.requireNonNull(sseProbeStreams, "sseProbeStreams must not be null");
        Objects.requireNonNull(lateIssues, "lateIssues must not be null");
        Objects.requireNonNull(burpNativeFields, "burpNativeFields must not be null");
        Objects.requireNonNull(signedInConsent, "signedInConsent must not be null");
    }

    public static CheckServices standalone() {
        return new CheckServices(McpEventLog.noop(), NoAuthStrategy::new, Optional::empty, Optional::empty,
                PrincipalRoster::empty, AccessLedger.noop(), PrincipalListings.unknown());
    }

    public CheckServices reportingLateIssues(CollaboratorWatch watch, LateIssueSink sink) {
        return new CheckServices(eventLog, authStrategy, watch, probeService, principals, accessLedger,
                principalListings, sseProbeStreams, sink, burpNativeFields, signedInConsent);
    }

    public CheckServices withSignedInConsent(SignedInConsent consent) {
        return new CheckServices(eventLog, authStrategy, collaboratorWatch, probeService, principals, accessLedger,
                principalListings, sseProbeStreams, lateIssues, burpNativeFields, consent);
    }
}
