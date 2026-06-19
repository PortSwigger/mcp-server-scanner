package com.mcpscanner.checks.registry;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
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
class ManagedPassiveCheckTest {

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "demo-passive", "Demo Passive", "desc",
            AuditIssueSeverity.LOW, ScanCheckType.PER_HOST,
            true, List.of());

    @Mock private ScanCheckSettings settings;
    @Mock private HttpRequestResponse baseRequestResponse;
    @Mock private AuditResult delegateResult;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void descriptorIsExposedDirectly() {
        ManagedPassiveCheck check = new StubPassive(settings, delegateResult);

        assertThat(check.descriptor()).isSameAs(DESCRIPTOR);
    }

    @Test
    void checkNameIsDescriptorDisplayName() {
        ManagedPassiveCheck check = new StubPassive(settings, delegateResult);

        assertThat(check.checkName()).isEqualTo("Demo Passive");
    }

    @Test
    void checkNameUsesBurpIssueNameWhenPresent() {
        CheckDescriptor descriptorWithBurpName = new CheckDescriptor(
                "demo-passive-burp", "UI Display", "desc",
                AuditIssueSeverity.LOW, ScanCheckType.PER_HOST,
                true, List.of(), Optional.of("Burp Issue Name"));
        ManagedPassiveCheck check = new StubPassive(settings, delegateResult, descriptorWithBurpName);

        assertThat(check.checkName()).isEqualTo("Burp Issue Name");
    }

    @Test
    void doCheckReturnsEmptyAuditResultWhenDisabled() {
        when(settings.isEnabled("demo-passive", true)).thenReturn(false);
        StubPassive check = new StubPassive(settings, delegateResult);

        AuditResult result = check.doCheck(baseRequestResponse);

        assertThat(result.auditIssues()).isEmpty();
        assertThat(check.runCheckInvocations).isZero();
    }

    @Test
    void doCheckRunsCheckWhenEnabled() {
        when(settings.isEnabled("demo-passive", true)).thenReturn(true);
        StubPassive check = new StubPassive(settings, delegateResult);

        AuditResult result = check.doCheck(baseRequestResponse);

        assertThat(result).isSameAs(delegateResult);
        assertThat(check.runCheckInvocations).isEqualTo(1);
    }

    @Test
    void constructorRejectsNullSettings() {
        assertThatThrownBy(() -> new StubPassive(null, delegateResult))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void logsStartedAndFinishMessagesOnSuccessfulRun() {
        when(settings.isEnabled("demo-passive", true)).thenReturn(true);
        AuditResult oneIssue = AuditResult.auditResult(List.of(issueWithName("X")));
        RecordingEventLog log = new RecordingEventLog();
        StubPassive check = new StubPassive(settings, oneIssue, DESCRIPTOR, log.asEventLog());

        check.doCheck(baseRequestResponse);

        assertThat(log.infos()).hasSize(2);
        assertThat(log.errors()).isEmpty();
        assertThat(log.infos().get(0)).isEqualTo("Scan check: demo-passive — started");
        assertThat(log.infos().get(1))
                .startsWith("Scan check: demo-passive — finished in ")
                .endsWith("ms, 1 issue");
    }

    @Test
    void pluralisesIssueCorrectly() {
        when(settings.isEnabled("demo-passive", true)).thenReturn(true);
        RecordingEventLog log = new RecordingEventLog();

        AuditResult zero = AuditResult.auditResult(List.of());
        new StubPassive(settings, zero, DESCRIPTOR, log.asEventLog())
                .doCheck(baseRequestResponse);
        assertThat(log.infos().get(1)).endsWith("ms, 0 issues");

        AuditResult one = AuditResult.auditResult(List.of(issueWithName("X")));
        new StubPassive(settings, one, DESCRIPTOR, log.asEventLog())
                .doCheck(baseRequestResponse);
        assertThat(log.infos().get(3)).endsWith("ms, 1 issue");

        AuditResult two = AuditResult.auditResult(List.of(issueWithName("X"), issueWithName("Y")));
        new StubPassive(settings, two, DESCRIPTOR, log.asEventLog())
                .doCheck(baseRequestResponse);
        assertThat(log.infos().get(5)).endsWith("ms, 2 issues");
    }

    @Test
    void logsErrorWhenCheckThrows() {
        when(settings.isEnabled("demo-passive", true)).thenReturn(true);
        RecordingEventLog log = new RecordingEventLog();
        RuntimeException boom = new IllegalStateException("kaboom");
        ThrowingPassive check = new ThrowingPassive(settings, log.asEventLog(), boom);

        assertThatThrownBy(() -> check.doCheck(baseRequestResponse))
                .isSameAs(boom);
        assertThat(log.infos()).containsExactly("Scan check: demo-passive — started");
        assertThat(log.errors()).hasSize(1);
        assertThat(log.errors().get(0).message())
                .isEqualTo("Scan check: demo-passive — threw IllegalStateException: kaboom");
        assertThat(log.errors().get(0).throwable()).isSameAs(boom);
    }

    @Test
    void doesNotLogWhenCheckIsDisabled() {
        when(settings.isEnabled("demo-passive", true)).thenReturn(false);
        RecordingEventLog log = new RecordingEventLog();
        StubPassive check = new StubPassive(settings, delegateResult, DESCRIPTOR, log.asEventLog());

        check.doCheck(baseRequestResponse);

        assertThat(log.infos()).isEmpty();
        assertThat(log.errors()).isEmpty();
    }

    private static AuditIssue issueWithName(String name) {
        AuditIssue issue = mock(AuditIssue.class);
        lenient().when(issue.name()).thenReturn(name);
        return issue;
    }

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

    private static final class StubPassive extends ManagedPassiveCheck {

        private final AuditResult result;
        private final CheckDescriptor descriptor;
        int runCheckInvocations = 0;

        StubPassive(ScanCheckSettings settings, AuditResult result) {
            this(settings, result, DESCRIPTOR);
        }

        StubPassive(ScanCheckSettings settings, AuditResult result, CheckDescriptor descriptor) {
            super(settings);
            this.result = result;
            this.descriptor = descriptor;
        }

        StubPassive(ScanCheckSettings settings, AuditResult result, CheckDescriptor descriptor,
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
        protected AuditResult runCheck(HttpRequestResponse baseRequestResponse) {
            runCheckInvocations++;
            return result;
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
            return ConsolidationAction.KEEP_BOTH;
        }
    }

    private static final class ThrowingPassive extends ManagedPassiveCheck {

        private final RuntimeException toThrow;

        ThrowingPassive(ScanCheckSettings settings, McpEventLog eventLog, RuntimeException toThrow) {
            super(settings, eventLog);
            this.toThrow = toThrow;
        }

        @Override
        public CheckDescriptor descriptor() {
            return DESCRIPTOR;
        }

        @Override
        protected AuditResult runCheck(HttpRequestResponse baseRequestResponse) {
            throw toThrow;
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
            return ConsolidationAction.KEEP_BOTH;
        }
    }
}
