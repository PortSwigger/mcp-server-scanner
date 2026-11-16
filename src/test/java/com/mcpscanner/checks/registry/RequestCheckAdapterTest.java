package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.RecordingChecks;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.checks.shared.scancontext.ScanNotices;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class RequestCheckAdapterTest {

    private final AuditIssue issue = mock(AuditIssue.class);
    private final HttpRequestResponse base = mock(HttpRequestResponse.class);
    private final Http http = mock(Http.class);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void registersWithBurpAsAPerRequestCheck() {
        assertThat(AdapterFixtures.registeredScanCheckType(adapterFor(new RecordingChecks.Request("r", List.of()), true)))
                .isEqualTo(ScanCheckType.PER_REQUEST);
    }

    @Test
    void auditsTheBaseRequestWithoutExposingTheInsertionPoint() {
        RecordingChecks.Request check = new RecordingChecks.Request("r", List.of(issue));

        List<AuditIssue> issues = adapterFor(check, true)
                .doCheck(base, mock(AuditInsertionPoint.class), http).auditIssues();

        assertThat(issues).containsExactly(issue);
        assertThat(check.calls).singleElement().satisfies(call -> {
            assertThat(call.base()).isSameAs(base);
            assertThat(call.insertionPoint()).isNull();
        });
    }

    @Test
    void aProbeCallIsLeftToItsBaseCall() {
        RecordingChecks.Request check = new RecordingChecks.Request("r", List.of(issue));

        List<AuditIssue> issues = adapterRunningOnProbes(check, true).doCheck(base, null, http).auditIssues();

        assertThat(issues).isEmpty();
        assertThat(check.calls).isEmpty();
    }

    @Test
    void aBaseCallIsStillAuditedWhenProbeCallsAreSkipped() {
        RecordingChecks.Request check = new RecordingChecks.Request("r", List.of(issue));

        adapterRunningOnProbes(check, false).doCheck(base, null, http);

        assertThat(check.calls).hasSize(1);
    }

    @Test
    void handsTheCheckTheProbeHttpItWasGiven() {
        RecordingChecks.Request check = new RecordingChecks.Request("r", List.of(issue));
        Http decorated = mock(Http.class);

        new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), McpEventLog.noop(), check, (checkId, sent) -> decorated)
                .doCheck(base, null, http);

        assertThat(check.calls).containsExactly(new RecordingChecks.Call(base, null, decorated));
    }

    @Test
    void disabledCheckIsNeverInvoked() {
        RecordingChecks.Request check = new RecordingChecks.Request("r", List.of(issue));

        assertThat(adapterFor(check, false).doCheck(base, null, http).auditIssues()).isEmpty();
        assertThat(check.calls).isEmpty();
    }

    @Test
    void rejectsACheckWhoseDescriptorDeclaresAnotherKind() {
        RecordingChecks.Request mislabelled = new RecordingChecks.Request(
                RecordingChecks.descriptorFor("r", CheckKind.INSERTION_POINT), List.of());

        assertThatThrownBy(() -> adapterFor(mislabelled, true)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void propagatesCheckFailuresAfterLoggingThem() {
        McpEventLog eventLog = new McpEventLog(null);
        RequestCheckAdapter adapter = new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog,
                new FailingRequestCheck());

        assertThatThrownBy(() -> adapter.doCheck(base, null, http)).isInstanceOf(IllegalStateException.class);
        assertThat(eventLog.snapshot()).anyMatch(entry -> entry.message().contains("failing — threw"));
    }

    @Test
    void clearingTheSessionClearsAConnectionScopedCheck() {
        ConnectionScopedRequest check = new ConnectionScopedRequest();

        new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), McpEventLog.noop(), check).clearConnectionState();

        assertThat(check.cleared).isEqualTo(1);
    }

    @Test
    void clearingTheSessionIgnoresACheckWithoutConnectionState() {
        assertThatCode(() -> adapterFor(new RecordingChecks.Request("r", List.of()), true).clearConnectionState())
                .doesNotThrowAnyException();
    }

    private static final class ConnectionScopedRequest implements RequestCheck, ConnectionScoped {

        private int cleared;

        @Override
        public CheckDescriptor descriptor() {
            return RecordingChecks.descriptorFor("scoped", CheckKind.REQUEST);
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, Http http) {
            return List.of();
        }

        @Override
        public void clearConnectionState() {
            cleared++;
        }
    }

    private static RequestCheckAdapter adapterRunningOnProbes(RecordingChecks.Request check, boolean probe) {
        return new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), McpEventLog.noop(), check,
                CheckInstrumentation.NONE, UpstreamExchanges.NONE, ConnectionReuse.withoutLocalAnswers(),
                IssueDestination.NONE, new ScanNotices(), base -> probe);
    }

    private static RequestCheckAdapter adapterFor(RecordingChecks.Request check, boolean enabled) {
        return new RequestCheckAdapter(AdapterFixtures.settingsAllowing(enabled), McpEventLog.noop(), check);
    }

    private static final class FailingRequestCheck implements RequestCheck {

        @Override
        public CheckDescriptor descriptor() {
            return RecordingChecks.descriptorFor("failing", CheckKind.REQUEST);
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, Http http) {
            throw new IllegalStateException("boom");
        }
    }
}
