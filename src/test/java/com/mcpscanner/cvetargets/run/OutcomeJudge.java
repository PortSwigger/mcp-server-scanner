package com.mcpscanner.cvetargets.run;

import com.mcpscanner.cvetargets.manifest.ExpectedOutcome;
import com.mcpscanner.cvetargets.manifest.Outcome;
import com.mcpscanner.cvetargets.manifest.SeverityRank;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

public final class OutcomeJudge {

    public Outcome observed(List<IssueSummary> issues) {
        return issues.isEmpty() ? Outcome.SILENT : Outcome.FIRE;
    }

    public Verdict judge(ExpectedOutcome expected, List<IssueSummary> issues, ProbeTally probes) {
        return judge(expected, issues, List.of(), probes);
    }

    public Verdict judge(ExpectedOutcome expected, List<IssueSummary> issues, List<IssueSummary> ambiguous,
                         ProbeTally probes) {
        Verdict verdict = judgeAttributed(expected, issues, probes);
        if (expected.outcome() == Outcome.SILENT && verdict.passed() && !ambiguous.isEmpty()) {
            return new Verdict(false, verdict.explanation() + ", but " + ambiguous.size() + " issue"
                    + (ambiguous.size() == 1 ? "" : "s") + " another check reported under the same name may be "
                    + "this check's: " + String.join(", ", ambiguous.stream().map(IssueSummary::name).toList()));
        }
        return verdict;
    }

    private Verdict judgeAttributed(ExpectedOutcome expected, List<IssueSummary> issues, ProbeTally probes) {
        List<IssueSummary> undeclared = issues.stream().filter(issue -> !expected.declares(issue.name())).toList();
        long matching = undeclared.stream().filter(matches(expected)).count();
        boolean outcomeMet = expected.outcome() == Outcome.FIRE ? matching > 0 : matching == 0;
        String observation = "expected " + expected.outcome() + describe(expected)
                + ", observed " + matching + " matching of " + undeclared.size()
                + (expected.alsoReports().isEmpty() ? "" : " undeclared") + " issues";
        if (expected.isKnownMiss()) {
            return new Verdict(outcomeMet, "known miss (" + expected.knownMiss() + "): " + observation);
        }
        if (expected.isKnownFlaky() && !outcomeMet) {
            return new Verdict(true, "known flaky (" + expected.knownFlaky() + "), not evidence: " + observation);
        }
        if (expected.outcome() == Outcome.SILENT && probes.reached() == 0) {
            return new Verdict(false, observation + ", but 0 of " + probes.sent() + " probe requests reached the target");
        }
        return unreportedDeclaration(expected, issues)
                .map(name -> new Verdict(false, observation + ", but the declared issue " + name + " was not reported"))
                .orElseGet(() -> new Verdict(outcomeMet, observation));
    }

    private static Optional<String> unreportedDeclaration(ExpectedOutcome expected, List<IssueSummary> issues) {
        return expected.alsoReports().stream()
                .filter(name -> issues.stream().noneMatch(issue -> name.equals(issue.name())))
                .findFirst();
    }

    private static Predicate<IssueSummary> matches(ExpectedOutcome expected) {
        return issue -> optionalEquals(expected.issueName(), issue.name())
                && optionalEquals(expected.severity(), issue.severity())
                && optionalEquals(expected.confidence(), issue.confidence())
                && SeverityRank.reaches(issue.severity(), expected.minimumSeverity());
    }

    private static boolean optionalEquals(Object expected, Object actual) {
        return expected == null || Objects.equals(expected, actual);
    }

    private static String describe(ExpectedOutcome expected) {
        StringBuilder filter = new StringBuilder();
        appendFilter(filter, "name", expected.issueName());
        appendFilter(filter, "severity", expected.severity());
        appendFilter(filter, "severity>", expected.minimumSeverity());
        appendFilter(filter, "confidence", expected.confidence());
        appendFilter(filter, "also reports", expected.alsoReports().isEmpty() ? null : expected.alsoReports());
        return filter.isEmpty() ? "" : " (" + filter + ")";
    }

    private static void appendFilter(StringBuilder filter, String label, Object value) {
        if (value != null) {
            filter.append(filter.isEmpty() ? "" : ", ").append(label).append('=').append(value);
        }
    }
}
