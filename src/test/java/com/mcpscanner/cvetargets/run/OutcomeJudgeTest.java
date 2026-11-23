package com.mcpscanner.cvetargets.run;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.cvetargets.manifest.ExpectedOutcome;
import com.mcpscanner.cvetargets.manifest.Outcome;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OutcomeJudgeTest {

    private static final IssueSummary FIRM_ORIGIN = new IssueSummary("Origin admitted", AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.FIRM, "http://127.0.0.1/mcp", "detail");

    private static final ProbeTally REACHED = new ProbeTally(3, 1);
    private static final ProbeTally NONE_REACHED = new ProbeTally(4, 0);

    private final OutcomeJudge judge = new OutcomeJudge();

    @Test
    void fireNeedsAtLeastOneIssue() {
        assertThat(judge.judge(ExpectedOutcome.of(Outcome.FIRE), List.of(FIRM_ORIGIN), REACHED).passed()).isTrue();
        assertThat(judge.judge(ExpectedOutcome.of(Outcome.FIRE), List.of(), REACHED).passed()).isFalse();
    }

    @Test
    void silentNeedsNoIssue() {
        assertThat(judge.judge(ExpectedOutcome.of(Outcome.SILENT), List.of(), REACHED).passed()).isTrue();
        assertThat(judge.judge(ExpectedOutcome.of(Outcome.SILENT), List.of(FIRM_ORIGIN), REACHED).passed()).isFalse();
    }

    @Test
    void fireWithCalibrationNeedsAMatchingIssue() {
        ExpectedOutcome certain = new ExpectedOutcome(Outcome.FIRE, "Origin admitted", null, AuditIssueConfidence.CERTAIN, null, null);

        Verdict verdict = judge.judge(certain, List.of(FIRM_ORIGIN), REACHED);

        assertThat(verdict.passed()).isFalse();
        assertThat(verdict.explanation()).isEqualTo(
                "expected FIRE (name=Origin admitted, confidence=CERTAIN), observed 0 matching of 1 issues");
    }

    @Test
    void silentWithANameIgnoresOtherIssues() {
        ExpectedOutcome silentForName = new ExpectedOutcome(Outcome.SILENT, "Host admitted", null, null, null, null);

        assertThat(judge.judge(silentForName, List.of(FIRM_ORIGIN), REACHED).passed()).isTrue();
    }

    @Test
    void silenceIgnoresAnIssueTheArmDeclaresItAlsoReports() {
        ExpectedOutcome silentButDeclared = ExpectedOutcome.of(Outcome.SILENT).alsoReporting(List.of("Origin admitted"));

        Verdict verdict = judge.judge(silentButDeclared, List.of(FIRM_ORIGIN), REACHED);

        assertThat(verdict.passed()).isTrue();
        assertThat(verdict.explanation()).isEqualTo(
                "expected SILENT (also reports=[Origin admitted]), observed 0 matching of 0 undeclared issues");
    }

    @Test
    void anUndeclaredIssueStillBreaksSilence() {
        ExpectedOutcome silentButDeclared = ExpectedOutcome.of(Outcome.SILENT).alsoReporting(List.of("Origin admitted"));

        assertThat(judge.judge(silentButDeclared, List.of(FIRM_ORIGIN, issueOf(AuditIssueSeverity.LOW)), REACHED)
                .passed()).isFalse();
    }

    @Test
    void aDeclaredIssueThatIsNotReportedFailsTheArm() {
        ExpectedOutcome silentButDeclared = ExpectedOutcome.of(Outcome.SILENT).alsoReporting(List.of("Origin admitted"));

        Verdict verdict = judge.judge(silentButDeclared, List.of(), REACHED);

        assertThat(verdict.passed()).isFalse();
        assertThat(verdict.explanation()).endsWith(", but the declared issue Origin admitted was not reported");
    }

    @Test
    void fireNeedsAnIssueBesidesTheDeclaredOnes() {
        ExpectedOutcome fireButDeclared = ExpectedOutcome.of(Outcome.FIRE).alsoReporting(List.of("Origin admitted"));

        assertThat(judge.judge(fireButDeclared, List.of(FIRM_ORIGIN), REACHED).passed()).isFalse();
        assertThat(judge.judge(fireButDeclared, List.of(FIRM_ORIGIN, issueOf(AuditIssueSeverity.LOW)), REACHED)
                .passed()).isTrue();
    }

    @Test
    void silenceAboveASeverityFloorAllowsOnlyIssuesBelowIt() {
        ExpectedOutcome silentFromLow = new ExpectedOutcome(Outcome.SILENT, null, null, null, AuditIssueSeverity.LOW, null);

        assertThat(judge.judge(silentFromLow, List.of(issueOf(AuditIssueSeverity.INFORMATION)), REACHED).passed()).isTrue();
        assertThat(judge.judge(silentFromLow, List.of(issueOf(AuditIssueSeverity.LOW)), REACHED).passed()).isFalse();
        assertThat(judge.judge(silentFromLow, List.of(issueOf(AuditIssueSeverity.HIGH)), REACHED).passed()).isFalse();
    }

    @Test
    void fireAboveASeverityFloorNeedsAnIssueAtOrAboveIt() {
        ExpectedOutcome fireFromMedium = new ExpectedOutcome(Outcome.FIRE, null, null, null, AuditIssueSeverity.MEDIUM, null);

        Verdict belowFloor = judge.judge(fireFromMedium,
                List.of(issueOf(AuditIssueSeverity.LOW), issueOf(AuditIssueSeverity.INFORMATION)), REACHED);

        assertThat(belowFloor.passed()).isFalse();
        assertThat(belowFloor.explanation()).isEqualTo("expected FIRE (severity>=MEDIUM), observed 0 matching of 2 issues");
        assertThat(judge.judge(fireFromMedium, List.of(issueOf(AuditIssueSeverity.MEDIUM)), REACHED).passed()).isTrue();
    }

    @Test
    void aFalsePositiveNeverReachesASeverityFloor() {
        ExpectedOutcome silentFromInformation = new ExpectedOutcome(Outcome.SILENT, null, null, null,
                AuditIssueSeverity.INFORMATION, null);

        assertThat(judge.judge(silentFromInformation, List.of(issueOf(AuditIssueSeverity.FALSE_POSITIVE)), REACHED)
                .passed()).isTrue();
    }

    private static IssueSummary issueOf(AuditIssueSeverity severity) {
        return new IssueSummary("Outbound request", severity, AuditIssueConfidence.FIRM, "http://127.0.0.1/mcp", "detail");
    }

    @Test
    void silenceIsVacuousWhenNoProbeRequestWasAnswered() {
        Verdict verdict = judge.judge(ExpectedOutcome.of(Outcome.SILENT), List.of(), NONE_REACHED);

        assertThat(verdict.passed()).isFalse();
        assertThat(verdict.explanation()).isEqualTo(
                "expected SILENT, observed 0 matching of 0 issues, but 0 of 4 probe requests reached the target");
    }

    @Test
    void fireIsJudgedOnIssuesWhateverTheProbesReached() {
        assertThat(judge.judge(ExpectedOutcome.of(Outcome.FIRE), List.of(FIRM_ORIGIN), NONE_REACHED).passed()).isTrue();
    }

    @Test
    void aKnownMissPassesUnexercisedButStillFailsIfTheCheckFires() {
        ExpectedOutcome knownMiss = new ExpectedOutcome(Outcome.SILENT, null, null, null, null, "check skips SSE");

        Verdict unexercised = judge.judge(knownMiss, List.of(), NONE_REACHED);

        assertThat(unexercised.passed()).isTrue();
        assertThat(unexercised.explanation()).isEqualTo(
                "known miss (check skips SSE): expected SILENT, observed 0 matching of 0 issues");
        assertThat(judge.judge(knownMiss, List.of(FIRM_ORIGIN), REACHED).passed()).isFalse();
    }

    @Test
    void aKnownFlakyFireArmPassesWhenItFiresAndIsMarkedNotEvidenceWhenItMisses() {
        ExpectedOutcome flaky = new ExpectedOutcome(Outcome.FIRE, null, null, null, null, null,
                "the server drops kept-alive connections");

        Verdict missed = judge.judge(flaky, List.of(), REACHED);

        assertThat(missed.passed()).isTrue();
        assertThat(missed.explanation()).isEqualTo("known flaky (the server drops kept-alive connections), not "
                + "evidence: expected FIRE, observed 0 matching of 0 issues");
        assertThat(judge.judge(flaky, List.of(FIRM_ORIGIN), REACHED).explanation())
                .isEqualTo("expected FIRE, observed 1 matching of 1 issues");
    }

    @Test
    void aSilentArmFailsWhenAnIssueItsCheckMayHaveRaisedCannotBeAttributed() {
        Verdict verdict = judge.judge(ExpectedOutcome.of(Outcome.SILENT), List.of(), List.of(FIRM_ORIGIN), REACHED);

        assertThat(verdict.passed()).isFalse();
        assertThat(verdict.explanation()).isEqualTo("expected SILENT, observed 0 matching of 0 issues, but 1 issue "
                + "another check reported under the same name may be this check's: Origin admitted");
    }

    @Test
    void aKnownMissStillFailsOnAnIssueItsCheckMayHaveRaised() {
        ExpectedOutcome knownMiss = new ExpectedOutcome(Outcome.SILENT, null, null, null, null, "check skips SSE");

        assertThat(judge.judge(knownMiss, List.of(), List.of(FIRM_ORIGIN), REACHED).passed()).isFalse();
    }

    @Test
    void anAmbiguousIssueNeverMakesAFireArmPass() {
        assertThat(judge.judge(ExpectedOutcome.of(Outcome.FIRE), List.of(), List.of(FIRM_ORIGIN), REACHED).passed())
                .isFalse();
    }

    @Test
    void observedOutcomeReflectsAnyIssue() {
        assertThat(judge.observed(List.of())).isEqualTo(Outcome.SILENT);
        assertThat(judge.observed(List.of(FIRM_ORIGIN))).isEqualTo(Outcome.FIRE);
    }
}
