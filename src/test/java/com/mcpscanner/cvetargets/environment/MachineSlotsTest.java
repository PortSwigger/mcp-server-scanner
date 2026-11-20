package com.mcpscanner.cvetargets.environment;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

class MachineSlotsTest {

    @TempDir
    Path slotsDirectory;

    private final List<String> log = java.util.Collections.synchronizedList(new ArrayList<>());

    @Test
    void grantsAsManySlotsAsConfiguredAndNoMore() {
        MachineSlots slots = slots(2, Pause.sleeping());

        try (ArmSlot first = slots.tryAcquire().orElseThrow(); ArmSlot second = slots.tryAcquire().orElseThrow()) {
            assertThat(slots.tryAcquire()).isEmpty();
        }
        assertThat(slots.tryAcquire()).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void waitsForAReleasedSlotAndSaysSoOnce() {
        MachineSlots slots = slots(1, duration -> Thread.yield());
        ArmSlot held = slots.acquire("check/target/vulnerable");

        CompletableFuture<ArmSlot> waiting = CompletableFuture.supplyAsync(() -> slots.acquire("check/target/fixed"));
        await().atMost(Duration.ofSeconds(5)).until(() -> !log.isEmpty());
        assertThat(waiting).isNotDone();
        held.close();

        await().atMost(Duration.ofSeconds(5)).pollInterval(Duration.ofMillis(20)).until(waiting::isDone);
        waiting.join().close();
        assertThat(log).hasSize(1).first().asString()
                .contains("check/target/fixed", "waiting for one of 1 machine-wide CVE target slots", slotsDirectory.toString());
    }

    @Test
    void aLargerFootprintTakesSeveralSlotsAtOnce() {
        MachineSlots slots = slots(3, Pause.sleeping());

        try (ArmSlot heavy = slots.tryAcquire(2).orElseThrow()) {
            assertThat(slots.tryAcquire(2)).isEmpty();
            try (ArmSlot light = slots.tryAcquire(1).orElseThrow()) {
                assertThat(slots.tryAcquire(1)).isEmpty();
            }
        }
        assertThat(slots.tryAcquire(3)).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void takesAllOfAFootprintsSlotsOrNoneSoWaitersNeverDeadlock() {
        MachineSlots slots = slots(2, Pause.sleeping());

        try (ArmSlot held = slots.tryAcquire(1).orElseThrow()) {
            assertThat(slots.tryAcquire(2)).isEmpty();
            assertThat(slots.tryAcquire(1)).isPresent().get().satisfies(ArmSlot::close);
        }
    }

    @Test
    void releasesTheSlotsItTookWhenALaterSlotCannotBeLocked() throws Exception {
        MachineSlots slots = slots(2, Pause.sleeping());
        java.nio.file.Files.createDirectories(slotsDirectory.resolve("slot-1.lock"));

        assertThatThrownBy(() -> slots.tryAcquire(2)).isInstanceOf(java.io.UncheckedIOException.class);

        assertThat(slots.tryAcquire(1)).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void aFootprintLargerThanTheMachineTakesEverySlot() {
        MachineSlots slots = slots(2, Pause.sleeping());

        try (ArmSlot everything = slots.tryAcquire(5).orElseThrow()) {
            assertThat(slots.tryAcquire(1)).isEmpty();
        }
    }

    @Test
    void sizesAFootprintInWholeSlotsOfFiveHundredAndTwelveMegabytes() {
        assertThat(MachineSlots.slotsFor(1)).isEqualTo(1);
        assertThat(MachineSlots.slotsFor(512)).isEqualTo(1);
        assertThat(MachineSlots.slotsFor(513)).isEqualTo(2);
        assertThat(MachineSlots.slotsFor(2048)).isEqualTo(4);
    }

    @Test
    void saysHowManySlotsALargerFootprintWaitsFor() {
        MachineSlots slots = slots(2, duration -> Thread.yield());
        ArmSlot held = slots.acquire("check/target/vulnerable");

        CompletableFuture<ArmSlot> waiting = CompletableFuture.supplyAsync(() -> slots.acquire("check/heavy/fixed", 2));
        await().atMost(Duration.ofSeconds(5)).until(() -> !log.isEmpty());
        held.close();

        await().atMost(Duration.ofSeconds(5)).pollInterval(Duration.ofMillis(20)).until(waiting::isDone);
        waiting.join().close();
        assertThat(log).first().asString().contains("check/heavy/fixed", "waiting for 2 of 2 machine-wide CVE target slots");
    }

    @Test
    void aWaitingLargerFootprintIsNotOvertakenByALaterSmallerOneInTheSameRun() {
        MachineSlots slots = slots(2, duration -> Thread.yield());
        ArmSlot held = slots.acquire("check/target/vulnerable");
        CompletableFuture<ArmSlot> heavy = CompletableFuture.supplyAsync(() -> slots.acquire("check/heavy/fixed", 2));
        await().atMost(Duration.ofSeconds(5)).until(() -> !log.isEmpty());

        CompletableFuture<ArmSlot> light = CompletableFuture.supplyAsync(() -> slots.acquire("check/light/fixed"));
        await().during(Duration.ofMillis(300)).atMost(Duration.ofSeconds(2)).until(() -> !light.isDone());
        held.close();
        await().atMost(Duration.ofSeconds(5)).pollInterval(Duration.ofMillis(20)).until(heavy::isDone);
        assertThat(light).isNotDone();

        heavy.join().close();
        await().atMost(Duration.ofSeconds(5)).pollInterval(Duration.ofMillis(20)).until(light::isDone);
        light.join().close();
    }

    @Test
    void refusesFewerThanOneSlot() {
        assertThatThrownBy(() -> slots(0, Pause.sleeping())).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one slot");
    }

    @Test
    void anotherProcessHoldingTheOnlySlotBlocksThisOne() throws Exception {
        Process holder = new ProcessBuilder(javaBinary(), "-cp", System.getProperty("java.class.path"),
                SlotHolderMain.class.getName(), slotsDirectory.toString())
                .redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try (BufferedReader output = new BufferedReader(new InputStreamReader(holder.getInputStream(), StandardCharsets.UTF_8))) {
            CompletableFuture<String> announcement = CompletableFuture.supplyAsync(() -> firstLine(output));
            await().atMost(Duration.ofSeconds(30)).pollInterval(Duration.ofMillis(50)).until(announcement::isDone);
            assertThat(announcement.join()).isEqualTo(SlotHolderMain.HELD);

            assertThat(slots(1, Pause.sleeping()).tryAcquire()).isEmpty();

            holder.getOutputStream().close();
            await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(50)).until(() -> !holder.isAlive());
            assertThat(slots(1, Pause.sleeping()).tryAcquire()).isPresent().get().satisfies(ArmSlot::close);
        } finally {
            holder.destroyForcibly();
        }
    }

    private MachineSlots slots(int count, Pause pause) {
        return new MachineSlots(slotsDirectory, count, pause, Duration.ofMinutes(1), log::add);
    }

    @Test
    void probingFromTheSameProcessNeverReleasesASlotItHolds() throws Exception {
        MachineSlots slots = slots(1, Pause.sleeping());
        try (ArmSlot held = slots.tryAcquire().orElseThrow()) {
            assertThat(slots.tryAcquire()).isEmpty();
            assertThat(slots.tryAcquire()).isEmpty();

            Process prober = new ProcessBuilder(javaBinary(), "-cp", System.getProperty("java.class.path"),
                    SlotProbeMain.class.getName(), slotsDirectory.toString())
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            await().atMost(Duration.ofSeconds(30)).pollInterval(Duration.ofMillis(50)).until(() -> !prober.isAlive());
            assertThat(prober.exitValue()).as("another process must still see the slot as taken").isEqualTo(SlotProbeMain.TAKEN);
        }
    }

    private static String firstLine(BufferedReader output) {
        try {
            return output.readLine();
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private static String javaBinary() {
        return ProcessHandle.current().info().command().orElse("java");
    }

    static final class SlotProbeMain {

        static final int TAKEN = 3;

        public static void main(String[] arguments) {
            boolean free = new MachineSlots(Path.of(arguments[0]), 1, Pause.sleeping(), Duration.ofMinutes(1),
                    System.err::println).tryAcquire().isPresent();
            System.exit(free ? 0 : TAKEN);
        }
    }

    static final class SlotHolderMain {

        static final String HELD = "held";

        public static void main(String[] arguments) throws IOException {
            try (ArmSlot slot = new MachineSlots(Path.of(arguments[0]), 1, Pause.sleeping(), Duration.ofMinutes(1),
                    System.err::println).tryAcquire().orElseThrow()) {
                System.out.println(HELD);
                System.out.flush();
                System.in.read();
            }
        }
    }
}
