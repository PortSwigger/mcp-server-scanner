package com.mcpscanner.access.comparison;

import burp.api.montoya.http.Http;
import com.mcpscanner.access.AccessComparison;
import com.mcpscanner.access.AccessComparisonRun;
import com.mcpscanner.access.SyntheticCall;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.crossidentity.PrincipalRequests;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

public final class CrossIdentityComparison implements AccessComparison {

    static final String CHECK_ACCESS_LABEL = "Check access";

    private final McpEventLog eventLog;
    private final Supplier<AuthStrategy> primaryAuth;
    private final Supplier<PrincipalRoster> principals;
    private final CrossIdentityPorts ports;
    private final Supplier<List<Principal>> synthetic;
    private final Consumer<SyntheticCall> syntheticCalls;

    public CrossIdentityComparison(McpEventLog eventLog, Supplier<AuthStrategy> primaryAuth,
                                   Supplier<PrincipalRoster> principals, CrossIdentityPorts ports) {
        this(eventLog, primaryAuth, principals, ports, () -> List.of(Principal.anonymous()), call -> { });
    }

    public CrossIdentityComparison(McpEventLog eventLog, Supplier<AuthStrategy> primaryAuth,
                                   Supplier<PrincipalRoster> principals, CrossIdentityPorts ports,
                                   Supplier<List<Principal>> synthetic, Consumer<SyntheticCall> syntheticCalls) {
        this.synthetic = synthetic;
        this.syntheticCalls = syntheticCalls;
        this.eventLog = eventLog;
        this.primaryAuth = primaryAuth;
        this.principals = principals;
        this.ports = ports;
    }

    @Override
    public AccessComparisonRun begin(Http http) {
        PrincipalRoster roster = principals.get();
        ComparisonTransport transport = new ComparisonTransport(http);
        ComparisonContext context = new ComparisonContext(new PrincipalRequests(primaryAuth, roster),
                new RunSessions(transport), transport, ports);
        return new CrossIdentityComparisonRun(roster, context, CheckLog.labelled(eventLog, CHECK_ACCESS_LABEL),
                new SameCredentialNotice(eventLog), new SyntheticCalls(synthetic.get(), context, syntheticCalls));
    }
}
