package com.mcpscanner.cvetargets.run;

import com.mcpscanner.cvetargets.manifest.TargetSelection;

import java.nio.file.Path;
import java.util.Optional;
import java.util.Properties;

public record HarnessSettings(Path targetsRoot, Path resultsRoot, TargetSelection selection, int slots, Path slotsDirectory,
                              int parallelArms, boolean allChecks, Path durationsFile) {

    static final String TARGETS_ROOT_PROPERTY = "cveTargets.root";
    static final String RESULTS_ROOT_PROPERTY = "cveTargets.results";
    static final String CHECK_PROPERTY = "cveTargets.check";
    static final String TARGET_PROPERTY = "cveTargets.target";
    static final String SMOKE_PROPERTY = "cveTargets.smoke";
    static final String SLOTS_PROPERTY = "cveTargets.slots";
    static final String SLOTS_DIRECTORY_PROPERTY = "cveTargets.slotsDir";
    static final String PARALLEL_PROPERTY = "cveTargets.parallel";
    static final String ALL_CHECKS_PROPERTY = "cveTargets.allChecks";
    static final String DURATIONS_PROPERTY = "cveTargets.durations";
    private static final String RESULTS_PARENT = "cve-targets";
    static final int DEFAULT_SLOTS = 2;

    public static HarnessSettings fromSystemProperties() {
        return fromProperties(System.getProperties());
    }

    static HarnessSettings fromProperties(Properties properties) {
        Optional<Integer> slots = property(properties, SLOTS_PROPERTY).map(value -> wholeNumber(value, "-PcveSlots"));
        Optional<Integer> parallel = property(properties, PARALLEL_PROPERTY)
                .map(value -> wholeNumber(value, "-PcveParallel"));
        int slotCount = slots.orElseGet(() -> Math.max(DEFAULT_SLOTS, parallel.orElse(DEFAULT_SLOTS)));
        Path resultsRoot = Path.of(properties.getProperty(RESULTS_ROOT_PROPERTY, "build/cve-targets")).toAbsolutePath();
        Path slotsDirectory = property(properties, SLOTS_DIRECTORY_PROPERTY).map(Path::of)
                .orElse(Path.of(properties.getProperty("user.home", ""), ".cache", "mcp-cve-targets", "slots"));
        return new HarnessSettings(
                Path.of(properties.getProperty(TARGETS_ROOT_PROPERTY, "cve-targets")).toAbsolutePath(),
                resultsRoot,
                new TargetSelection(property(properties, CHECK_PROPERTY), property(properties, TARGET_PROPERTY),
                        Boolean.parseBoolean(properties.getProperty(SMOKE_PROPERTY))),
                slotCount,
                slotsDirectory,
                parallel.orElse(slotCount),
                Boolean.parseBoolean(properties.getProperty(ALL_CHECKS_PROPERTY)),
                property(properties, DURATIONS_PROPERTY).map(Path::of)
                        .orElseGet(() -> besideSlots(slotsDirectory, "durations").resolve(runName(resultsRoot) + ".json")));
    }

    public Path recorderLocksDirectory() {
        return besideSlots(slotsDirectory, "recorder");
    }

    private static Path besideSlots(Path slotsDirectory, String name) {
        return slotsDirectory.toAbsolutePath().getParent().resolve(name);
    }

    private static String runName(Path resultsRoot) {
        int parent = lastIndexOf(resultsRoot, RESULTS_PARENT);
        return parent < 0 || parent == resultsRoot.getNameCount() - 1
                ? resultsRoot.getFileName().toString()
                : resultsRoot.subpath(parent + 1, resultsRoot.getNameCount()).toString();
    }

    private static int lastIndexOf(Path path, String name) {
        for (int index = path.getNameCount() - 1; index >= 0; index--) {
            if (path.getName(index).toString().equals(name)) {
                return index;
            }
        }
        return -1;
    }

    private static int wholeNumber(String value, String option) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException notANumber) {
            throw new IllegalArgumentException(option + " must be a whole number, got " + value);
        }
    }

    private static Optional<String> property(Properties properties, String name) {
        return Optional.ofNullable(properties.getProperty(name)).map(String::strip).filter(value -> !value.isEmpty());
    }
}
