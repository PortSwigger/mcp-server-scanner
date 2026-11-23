package com.mcpscanner.access.comparison;

import com.mcpscanner.checks.api.crossidentity.FakeMcpTarget;
import com.mcpscanner.checks.api.crossidentity.FakeReply;
import com.mcpscanner.checks.api.crossidentity.TestPrincipals;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.access.AccessComparisonRun;
import com.mcpscanner.access.SyntheticCall;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.logging.McpEventLog;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ComparisonHarness {

    private Principal owner = owner(Optional.empty());
    private final List<Principal> compared = new ArrayList<>();
    private RecordingLedger ledger = new RecordingLedger();
    private Principal auditOwner;
    private ObjectReferences references = ObjectReferences.ALL;
    private List<Principal> synthetic = List.of(Principal.anonymous());
    private final List<SyntheticCall> syntheticCalls = new ArrayList<>();

    static ComparisonHarness withPeerB() {
        return new ComparisonHarness().with(peer("B"));
    }

    static Principal owner(Optional<String> marker) {
        return TestPrincipals.owner(marker);
    }

    static Principal peer(String token) {
        return TestPrincipals.peer(token);
    }

    static Principal identity(String token, PrincipalRole role, Map<String, String> headers, Optional<String> marker,
                              Map<String, String> owned) {
        return TestPrincipals.identity(token, role, headers, marker, owned);
    }

    ComparisonHarness ownerMarker(String marker) {
        owner = owner(Optional.of(marker));
        return this;
    }

    ComparisonHarness owner(Principal value) {
        owner = value;
        return this;
    }

    ComparisonHarness auditAs(Principal value) {
        auditOwner = value;
        return this;
    }

    ComparisonHarness with(Principal principal) {
        compared.add(principal);
        return this;
    }

    ComparisonHarness references(ObjectReferences value) {
        references = value;
        return this;
    }

    ComparisonHarness synthetic(Principal... principals) {
        synthetic = List.of(principals);
        return this;
    }

    List<SyntheticCall> syntheticCalls() {
        return List.copyOf(syntheticCalls);
    }

    ComparisonHarness ledger(RecordingLedger value) {
        ledger = value;
        return this;
    }

    Run run(Function<HttpRequest, FakeReply> server, HttpRequest seed) {
        McpEventLog eventLog = new McpEventLog(null);
        FakeMcpTarget target = new FakeMcpTarget(server);
        CrossIdentityComparison comparison = new CrossIdentityComparison(eventLog,
                () -> new BearerTokenAuthStrategy("A"), () -> PrincipalRoster.of(owner, compared),
                CrossIdentityPorts.of(ledger, ledger, references), () -> synthetic, syntheticCalls::add);
        HttpRequest routed = auditOwner == null ? seed
                : seed.withHeader(ScannerSentinels.IDENTITY_HEADER, auditOwner.id());
        var base = target.exchange(routed);
        List<AuditIssue> issues;
        try (AccessComparisonRun comparisons = comparison.begin(target.http())) {
            issues = comparisons.compare(base);
        }
        List<HttpRequest> sent = target.sent().subList(1, target.sent().size());
        List<Decision> decisions = decisions(eventLog);
        return new Run(issues, sent, decisions.stream().map(Decision::name).toList(), decisions, infoLines(eventLog),
                ledger);
    }

    private static List<String> infoLines(McpEventLog eventLog) {
        return eventLog.snapshot().stream().filter(entry -> entry.level() == McpEventLog.Level.INFO)
                .map(McpEventLog.LogEntry::message).toList();
    }

    private static final Pattern DECISION = Pattern.compile(
            "^" + Pattern.quote(CrossIdentityComparison.CHECK_ACCESS_LABEL + " — ") + "(.+?)(?: as (\\S+))?: ([^ ]+)$");

    private static List<Decision> decisions(McpEventLog eventLog) {
        return eventLog.snapshot().stream()
                .filter(entry -> entry.level() == McpEventLog.Level.DEBUG)
                .map(entry -> DECISION.matcher(entry.message()))
                .filter(Matcher::matches)
                .map(match -> new Decision(match.group(2), match.group(3)))
                .toList();
    }

    record Decision(String principalName, String name) {
    }

    record Run(List<AuditIssue> issues, List<HttpRequest> sent, List<String> decisions, List<Decision> attributed,
               List<String> infoLines, RecordingLedger ledger) {

        List<String> decisionsOf(String principalName) {
            return attributed.stream().filter(decision -> principalName.equals(decision.principalName()))
                    .map(Decision::name).toList();
        }

        boolean firedFamily(String family) {
            return issues.stream().anyMatch(issue -> issue.detail().contains("Probe: " + family + "."));
        }
    }
}
