package com.mcpscanner.cvetargets.run;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.mcpscanner.cvetargets.manifest.Outcome;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

public final class RunSummary {

    static final String FILE = "summary.json";
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final Comparator<ArmResult> BY_ARM = Comparator.comparing(ArmResult::check)
            .thenComparing(ArmResult::target).thenComparing(ArmResult::arm);

    private final Path resultsRoot;

    public RunSummary(Path resultsRoot) {
        this.resultsRoot = resultsRoot;
    }

    public Path write(List<ArmResult> results) {
        Path file = resultsRoot.resolve(FILE);
        try {
            Files.createDirectories(resultsRoot);
            JSON.writeValue(file.toFile(), new Summary(results.stream().sorted(BY_ARM).map(SummaryArm::of).toList()));
            return file;
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write " + file, e);
        }
    }

    record Summary(List<SummaryArm> arms) {
    }

    record SummaryArm(String check, String target, String arm, Outcome expected, Outcome observed, boolean passed,
                      String verdict, long durationMillis, Map<String, List<String>> otherCheckIssues, String notRunnable, String result) {

        static SummaryArm of(ArmResult result) {
            return new SummaryArm(result.check(), result.target(), result.arm(), result.expected().outcome(),
                    result.observed(), result.passed(), result.verdict(), result.durationMillis(), issueNames(result.otherCheckIssues()),
                    result.notRunnable(), ResultWriter.relativeFile(result).toString());
        }

        private static Map<String, List<String>> issueNames(Map<String, List<IssueSummary>> issues) {
            return issues.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey,
                    entry -> entry.getValue().stream().map(IssueSummary::name).toList(),
                    (first, second) -> first, TreeMap::new));
        }
    }
}
