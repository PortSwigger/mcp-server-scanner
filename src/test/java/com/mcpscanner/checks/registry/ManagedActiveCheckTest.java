package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManagedActiveCheckTest {

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "demo-active", "Demo", "desc",
            AuditIssueSeverity.MEDIUM, ScanCheckType.PER_REQUEST,
            true, List.of());

    @Mock private ScanCheckSettings settings;
    @Mock private HttpRequestResponse baseRequestResponse;
    @Mock private AuditInsertionPoint insertionPoint;
    @Mock private Http http;
    @Mock private AuditResult delegateResult;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void descriptorIsExposedDirectly() {
        ManagedActiveCheck check = new StubActive(settings, delegateResult);

        assertThat(check.descriptor()).isSameAs(DESCRIPTOR);
    }

    @Test
    void checkNameIsDescriptorDisplayName() {
        ManagedActiveCheck check = new StubActive(settings, delegateResult);

        assertThat(check.checkName()).isEqualTo("Demo");
    }

    @Test
    void checkNameUsesBurpIssueNameWhenPresent() {
        CheckDescriptor descriptorWithBurpName = new CheckDescriptor(
                "demo-active-burp", "UI Display", "desc",
                AuditIssueSeverity.MEDIUM, ScanCheckType.PER_REQUEST,
                true, List.of(), Optional.of("Burp Issue Name"));
        ManagedActiveCheck check = new StubActive(settings, delegateResult, descriptorWithBurpName);

        assertThat(check.checkName()).isEqualTo("Burp Issue Name");
    }

    @Test
    void consolidateByName_returnsKeepExistingWhenBothMatch() {
        StubActive check = new StubActive(settings, delegateResult);

        ConsolidationAction action = check.callConsolidateByName(
                "My Issue", issueWithName("My Issue"), issueWithName("My Issue"));

        assertThat(action).isEqualTo(ConsolidationAction.KEEP_EXISTING);
    }

    @Test
    void consolidateByName_returnsKeepBothWhenNamesDiffer() {
        StubActive check = new StubActive(settings, delegateResult);

        ConsolidationAction action = check.callConsolidateByName(
                "My Issue", issueWithName("My Issue"), issueWithName("Other Issue"));

        assertThat(action).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    @Test
    void consolidateByName_returnsKeepBothWhenNeitherMatchesExpectedName() {
        StubActive check = new StubActive(settings, delegateResult);

        ConsolidationAction action = check.callConsolidateByName(
                "My Issue", issueWithName("Unrelated"), issueWithName("Unrelated"));

        assertThat(action).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    private static AuditIssue issueWithName(String name) {
        AuditIssue issue = mock(AuditIssue.class);
        lenient().when(issue.name()).thenReturn(name);
        return issue;
    }

    @Test
    void doCheckReturnsEmptyAuditResultWhenDisabled() {
        when(settings.isEnabled("demo-active", true)).thenReturn(false);
        StubActive check = new StubActive(settings, delegateResult);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        assertThat(check.runCheckInvocations).isZero();
    }

    @Test
    void doCheckRunsCheckWhenEnabled() {
        when(settings.isEnabled("demo-active", true)).thenReturn(true);
        StubActive check = new StubActive(settings, delegateResult);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result).isSameAs(delegateResult);
        assertThat(check.runCheckInvocations).isEqualTo(1);
    }

    @Test
    void constructorRejectsNullSettings() {
        assertThatThrownBy(() -> new StubActive(null, delegateResult))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void logsStartedAndFinishMessagesOnSuccessfulRun() {
        when(settings.isEnabled("demo-active", true)).thenReturn(true);
        AuditResult oneIssue = AuditResult.auditResult(List.of(issueWithName("X")));
        RecordingEventLog log = new RecordingEventLog();
        StubActive check = new StubActive(settings, oneIssue, DESCRIPTOR, log.asEventLog());

        check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(log.infos()).hasSize(2);
        assertThat(log.errors()).isEmpty();
        assertThat(log.infos().get(0)).isEqualTo("Scan check: demo-active — started");
        assertThat(log.infos().get(1))
                .startsWith("Scan check: demo-active — finished in ")
                .endsWith("ms, 1 issue");
    }

    @Test
    void pluralisesIssueCorrectly() {
        when(settings.isEnabled("demo-active", true)).thenReturn(true);
        RecordingEventLog log = new RecordingEventLog();

        AuditResult zero = AuditResult.auditResult(List.of());
        new StubActive(settings, zero, DESCRIPTOR, log.asEventLog())
                .doCheck(baseRequestResponse, insertionPoint, http);
        assertThat(log.infos().get(1)).endsWith("ms, 0 issues");

        AuditResult one = AuditResult.auditResult(List.of(issueWithName("X")));
        new StubActive(settings, one, DESCRIPTOR, log.asEventLog())
                .doCheck(baseRequestResponse, insertionPoint, http);
        assertThat(log.infos().get(3)).endsWith("ms, 1 issue");

        AuditResult two = AuditResult.auditResult(List.of(issueWithName("X"), issueWithName("Y")));
        new StubActive(settings, two, DESCRIPTOR, log.asEventLog())
                .doCheck(baseRequestResponse, insertionPoint, http);
        assertThat(log.infos().get(5)).endsWith("ms, 2 issues");
    }

    @Test
    void logsErrorWhenCheckThrows() {
        when(settings.isEnabled("demo-active", true)).thenReturn(true);
        RecordingEventLog log = new RecordingEventLog();
        RuntimeException boom = new IllegalStateException("kaboom");
        ThrowingActive check = new ThrowingActive(settings, log.asEventLog(), boom);

        assertThatThrownBy(() -> check.doCheck(baseRequestResponse, insertionPoint, http))
                .isSameAs(boom);
        assertThat(log.infos()).containsExactly("Scan check: demo-active — started");
        assertThat(log.errors()).hasSize(1);
        assertThat(log.errors().get(0).message())
                .isEqualTo("Scan check: demo-active — threw IllegalStateException: kaboom");
        assertThat(log.errors().get(0).throwable()).isSameAs(boom);
    }

    @Test
    void doesNotLogWhenCheckIsDisabled() {
        when(settings.isEnabled("demo-active", true)).thenReturn(false);
        RecordingEventLog log = new RecordingEventLog();
        StubActive check = new StubActive(settings, delegateResult, DESCRIPTOR, log.asEventLog());

        check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(log.infos()).isEmpty();
        assertThat(log.errors()).isEmpty();
    }

    /**
     * Wraps a real {@link McpEventLog} (the production class — not a mock) and exposes the
     * captured entries split by level, so assertions describe behaviour rather than
     * interactions.
     */
    private static final class RecordingEventLog {

        private final McpEventLog delegate = new McpEventLog(null);

        McpEventLog asEventLog() {
            return delegate;
        }

        List<String> infos() {
            return delegate.snapshot().stream()
                    .filter(e -> e.level() == McpEventLog.Level.INFO)
                    .map(McpEventLog.LogEntry::message)
                    .toList();
        }

        List<McpEventLog.LogEntry> errors() {
            return delegate.snapshot().stream()
                    .filter(e -> e.level() == McpEventLog.Level.ERROR)
                    .toList();
        }
    }

    private static final class StubActive extends ManagedActiveCheck {

        private final AuditResult result;
        private final CheckDescriptor descriptor;
        int runCheckInvocations = 0;

        StubActive(ScanCheckSettings settings, AuditResult result) {
            this(settings, result, DESCRIPTOR);
        }

        StubActive(ScanCheckSettings settings, AuditResult result, CheckDescriptor descriptor) {
            super(settings);
            this.result = result;
            this.descriptor = descriptor;
        }

        StubActive(ScanCheckSettings settings, AuditResult result, CheckDescriptor descriptor,
                   McpEventLog eventLog) {
            super(settings, eventLog);
            this.result = result;
            this.descriptor = descriptor;
        }

        @Override
        public CheckDescriptor descriptor() {
            return descriptor;
        }

        @Override
        protected AuditResult runCheck(HttpRequestResponse baseRequestResponse,
                                       AuditInsertionPoint insertionPoint, Http http) {
            runCheckInvocations++;
            return result;
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
            return ConsolidationAction.KEEP_BOTH;
        }

        ConsolidationAction callConsolidateByName(String issueName, AuditIssue existing, AuditIssue incoming) {
            return consolidateByName(issueName, existing, incoming);
        }
    }

    private static final class ThrowingActive extends ManagedActiveCheck {

        private final RuntimeException toThrow;

        ThrowingActive(ScanCheckSettings settings, McpEventLog eventLog, RuntimeException toThrow) {
            super(settings, eventLog);
            this.toThrow = toThrow;
        }

        @Override
        public CheckDescriptor descriptor() {
            return DESCRIPTOR;
        }

        @Override
        protected AuditResult runCheck(HttpRequestResponse baseRequestResponse,
                                       AuditInsertionPoint insertionPoint, Http http) {
            throw toThrow;
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
            return ConsolidationAction.KEEP_BOTH;
        }
    }
}
