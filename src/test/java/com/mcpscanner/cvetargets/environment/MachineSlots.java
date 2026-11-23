package com.mcpscanner.cvetargets.environment;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

public final class MachineSlots {

    private static final Duration POLL_INTERVAL = Duration.ofSeconds(2);
    private static final int MEGABYTES_PER_SLOT = 512;
    private static final Set<Path> HELD_BY_THIS_PROCESS = ConcurrentHashMap.newKeySet();

    private final Path directory;
    private final int count;
    private final Pause pause;
    private final Duration reminderInterval;
    private final Consumer<String> log;
    private final ReentrantLock arrivalOrder = new ReentrantLock(true);

    public MachineSlots(Path directory, int count, Pause pause, Duration reminderInterval, Consumer<String> log) {
        if (count < 1) {
            throw new IllegalArgumentException("CVE target runs need at least one slot, got " + count);
        }
        this.directory = directory;
        this.count = count;
        this.pause = pause;
        this.reminderInterval = reminderInterval;
        this.log = log;
    }

    public static int slotsFor(int footprintMb) {
        return Math.max(1, (footprintMb + MEGABYTES_PER_SLOT - 1) / MEGABYTES_PER_SLOT);
    }

    public ArmSlot acquire(String armLabel) {
        return acquire(armLabel, 1);
    }

    public ArmSlot acquire(String armLabel, int wanted) {
        arrivalOrder.lock();
        try {
            return acquireInTurn(armLabel, wanted);
        } finally {
            arrivalOrder.unlock();
        }
    }

    private ArmSlot acquireInTurn(String armLabel, int wanted) {
        Instant nextReminder = Instant.MIN;
        while (true) {
            Optional<ArmSlot> slot = tryAcquire(wanted);
            if (slot.isPresent()) {
                return slot.get();
            }
            if (!Instant.now().isBefore(nextReminder)) {
                log.accept(armLabel + ": waiting for " + (wanted == 1 ? "one" : Math.min(wanted, count)) + " of "
                        + count + " machine-wide CVE target slots under " + directory
                        + " (other runs hold them; raise with -PcveSlots)");
                nextReminder = Instant.now().plus(reminderInterval);
            }
            pause.pause(POLL_INTERVAL);
        }
    }

    Optional<ArmSlot> tryAcquire() {
        return tryAcquire(1);
    }

    Optional<ArmSlot> tryAcquire(int wanted) {
        int needed = Math.min(Math.max(wanted, 1), count);
        List<SlotLock> held = new ArrayList<>();
        try {
            for (int index = 0; index < count && held.size() < needed; index++) {
                tryLock(directory.resolve("slot-" + index + ".lock")).ifPresent(held::add);
            }
        } catch (RuntimeException lockFailure) {
            new ArmSlot(held).close();
            throw lockFailure;
        }
        if (held.size() == needed) {
            return Optional.of(new ArmSlot(held));
        }
        new ArmSlot(held).close();
        return Optional.empty();
    }

    private Optional<SlotLock> tryLock(Path file) {
        Path key = file.toAbsolutePath().normalize();
        if (!HELD_BY_THIS_PROCESS.add(key)) {
            return Optional.empty();
        }
        Optional<SlotLock> slot = Optional.empty();
        try {
            slot = lockFreshChannel(file, () -> HELD_BY_THIS_PROCESS.remove(key));
            return slot;
        } finally {
            if (slot.isEmpty()) {
                HELD_BY_THIS_PROCESS.remove(key);
            }
        }
    }

    private Optional<SlotLock> lockFreshChannel(Path file, Runnable onRelease) {
        FileChannel channel = open(file);
        try {
            FileLock lock = channel.tryLock();
            if (lock != null) {
                return Optional.of(new SlotLock(channel, lock, onRelease));
            }
            channel.close();
            return Optional.empty();
        } catch (IOException e) {
            UncheckedIOException failure = new UncheckedIOException("cannot lock " + file, e);
            try {
                channel.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            throw failure;
        }
    }

    private FileChannel open(Path file) {
        try {
            Files.createDirectories(directory);
            return FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open CVE target slot " + file, e);
        }
    }
}
