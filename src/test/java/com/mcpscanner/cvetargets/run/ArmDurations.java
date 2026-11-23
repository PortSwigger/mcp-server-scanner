package com.mcpscanner.cvetargets.run;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.OptionalLong;
import java.util.TreeMap;
import java.util.function.Consumer;

public final class ArmDurations {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final TypeReference<TreeMap<String, Long>> HISTORY = new TypeReference<>() {
    };

    private final Path file;
    private final Consumer<String> log;
    private final Map<String, Long> known;
    private boolean unreadableReported;

    public ArmDurations(Path file, Consumer<String> log) {
        this.file = file;
        this.log = log;
        this.known = onDisk();
    }

    public OptionalLong recorded(ArmKey arm) {
        Long ranMillis = known.get(arm.text());
        return ranMillis == null ? OptionalLong.empty() : OptionalLong.of(ranMillis);
    }

    public synchronized void record(ArmResult result) {
        long ranMillis = ranMillis(result);
        if (!ranToTheEnd(result) || ranMillis <= 0) {
            return;
        }
        Map<String, Long> history = onDisk();
        history.put(ArmKey.of(result).text(), ranMillis);
        replace(history);
    }

    private static boolean ranToTheEnd(ArmResult result) {
        return result.notRunnable() == null && result.error() == null;
    }

    private static long ranMillis(ArmResult result) {
        return result.durationMillis() - result.phases().getOrDefault(ArmPhase.SLOT_WAIT.jsonName(), 0L);
    }

    private synchronized Map<String, Long> onDisk() {
        try {
            TreeMap<String, Long> history = JSON.readValue(Files.readString(file), HISTORY);
            return history == null ? new TreeMap<>() : history;
        } catch (NoSuchFileException absent) {
            return new TreeMap<>();
        } catch (IOException unreadable) {
            reportUnreadable(unreadable);
            return new TreeMap<>();
        }
    }

    private void reportUnreadable(IOException unreadable) {
        if (!unreadableReported) {
            unreadableReported = true;
            log.accept("cve-targets: ignoring unreadable arm durations " + file + ": " + unreadable.getMessage());
        }
    }

    private void replace(Map<String, Long> history) {
        Path written = null;
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            written = Files.createTempFile(file.toAbsolutePath().getParent(), file.getFileName() + ".", ".tmp");
            JSON.writeValue(written.toFile(), history);
            Files.move(written, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException failed) {
            log.accept("cve-targets: cannot record arm durations in " + file + ": " + failed.getMessage());
            deleteQuietly(written);
        }
    }

    private static void deleteQuietly(Path written) {
        if (written == null) {
            return;
        }
        try {
            Files.deleteIfExists(written);
        } catch (IOException ignored) {
            written.toFile().deleteOnExit();
        }
    }
}
