package com.mcpscanner.cvetargets.environment;

import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.ManifestFixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SlotLimitedEnvironmentTest {

    @TempDir
    Path root;

    @TempDir
    Path slotsDirectory;

    private final List<String> order = new ArrayList<>();

    @Test
    void holdsASlotFromBeforeStartUntilAfterTeardown() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 1, Pause.sleeping(), Duration.ofMinutes(1), order::add);
        TargetEnvironment environment = new SlotLimitedEnvironment(recording(), slots);

        RunningArm arm = environment.start(target(), target().manifest().arms().get(0));
        order.add("slot free while running: " + slots.tryAcquire().isPresent());
        arm.close();

        assertThat(order).containsExactly("start", "slot free while running: false", "teardown");
        assertThat(slots.tryAcquire()).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void reservingTakesTheSlotBeforeTheArmStartsAndTheArmKeepsItUntilTeardown() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 1, Pause.sleeping(), Duration.ofMinutes(1), order::add);
        SlotLimitedEnvironment environment = new SlotLimitedEnvironment(recording(), slots);

        ReservedArm reserved = environment.reserve(target(), target().manifest().arms().get(0));
        order.add("slot free while reserved: " + slots.tryAcquire().isPresent());
        RunningArm arm = reserved.start();
        reserved.close();
        order.add("slot free while running: " + slots.tryAcquire().isPresent());
        arm.close();

        assertThat(order).containsExactly("slot free while reserved: false", "start",
                "slot free while running: false", "teardown");
        assertThat(slots.tryAcquire()).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void closingAReservationThatNeverStartedReleasesItsSlot() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 1, Pause.sleeping(), Duration.ofMinutes(1), order::add);

        new SlotLimitedEnvironment(recording(), slots).reserve(target(), target().manifest().arms().get(0)).close();

        assertThat(order).isEmpty();
        assertThat(slots.tryAcquire()).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void aClosedReservationNeverStartsItsArm() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 1, Pause.sleeping(), Duration.ofMinutes(1), order::add);
        ReservedArm reserved = new SlotLimitedEnvironment(recording(), slots)
                .reserve(target(), target().manifest().arms().get(0));
        reserved.close();

        assertThatThrownBy(reserved::start).isInstanceOf(IllegalStateException.class);
        assertThat(order).isEmpty();
    }

    @Test
    void releasesTheSlotWhenStartingThrowsAnError() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 1, Pause.sleeping(), Duration.ofMinutes(1), order::add);
        TargetEnvironment failing = (target, arm) -> {
            throw new AssertionError("broken fixture");
        };

        assertThatThrownBy(() -> new SlotLimitedEnvironment(failing, slots).start(target(), target().manifest().arms().get(0)))
                .isInstanceOf(AssertionError.class);
        assertThat(slots.tryAcquire()).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void releasesTheSlotWhenTheArmFailsToStart() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 1, Pause.sleeping(), Duration.ofMinutes(1), order::add);
        TargetEnvironment failing = (target, arm) -> {
            throw new EnvironmentException("build failed");
        };

        assertThatThrownBy(() -> new SlotLimitedEnvironment(failing, slots).start(target(), target().manifest().arms().get(0)))
                .hasMessage("build failed");
        assertThat(slots.tryAcquire()).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void takesTheDelegatesReservationBeforeTheSlotAndReleasesBothWhenClosedUnstarted() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 1, Pause.sleeping(), Duration.ofMinutes(1), order::add);

        new SlotLimitedEnvironment(reserving(slots), slots).reserve(target(), target().manifest().arms().get(0)).close();

        assertThat(order).containsExactly("delegate reserved, slot free: true", "delegate reservation released");
        assertThat(slots.tryAcquire()).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void startsTheDelegatesReservationAndKeepsTheSlotUntilTeardown() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 1, Pause.sleeping(), Duration.ofMinutes(1), order::add);

        RunningArm arm = new SlotLimitedEnvironment(reserving(slots), slots)
                .start(target(), target().manifest().arms().get(0));
        order.add("slot free while running: " + slots.tryAcquire().isPresent());
        arm.close();

        assertThat(order).containsExactly("delegate reserved, slot free: true", "start",
                "slot free while running: false", "teardown");
        assertThat(slots.tryAcquire()).isPresent().get().satisfies(ArmSlot::close);
    }

    @Test
    void releasesTheDelegatesReservationWhenNoSlotCanBeTaken() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 1, Pause.sleeping(), Duration.ofMinutes(1), message -> {
            throw new IllegalStateException("gave up waiting");
        });
        ArmSlot occupied = slots.tryAcquire().orElseThrow();

        assertThatThrownBy(() -> new SlotLimitedEnvironment(reserving(slots), slots)
                .reserve(target(), target().manifest().arms().get(0)))
                .hasMessage("gave up waiting");
        occupied.close();

        assertThat(order).containsExactly("delegate reserved, slot free: false", "delegate reservation released");
    }

    private TargetEnvironment reserving(MachineSlots slots) {
        TargetEnvironment recording = recording();
        return new TargetEnvironment() {
            @Override
            public RunningArm start(LoadedTarget target, com.mcpscanner.cvetargets.manifest.TargetArm arm) {
                return recording.start(target, arm);
            }

            @Override
            public ReservedArm reserve(LoadedTarget target, com.mcpscanner.cvetargets.manifest.TargetArm arm) {
                order.add("delegate reserved, slot free: " + slots.tryAcquire().map(slot -> {
                    slot.close();
                    return true;
                }).orElse(false));
                return new ReservedArm(() -> recording.start(target, arm),
                        () -> order.add("delegate reservation released"));
            }
        };
    }

    private TargetEnvironment recording() {
        return (target, arm) -> {
            order.add("start");
            return new RunningArm() {
                @Override
                public URI endpoint() {
                    return URI.create("http://127.0.0.1:1/mcp");
                }

                @Override
                public void close() {
                    order.add("teardown");
                }
            };
        };
    }

    @Test
    void aTargetDeclaringALargerFootprintHoldsThatManySlots() {
        MachineSlots slots = new MachineSlots(slotsDirectory, 3, Pause.sleeping(), Duration.ofMinutes(1), order::add);
        ManifestFixtures.writeTarget(root, "check-a", "heavy-target", ManifestFixtures.VALID_MANIFEST
                .formatted("heavy-target", "check-a").replaceFirst("\\{", "{\"footprintMb\": 1024,"));
        LoadedTarget heavy = ManifestFixtures.loadOnly(root, "check-a", "heavy-target");

        RunningArm arm = new SlotLimitedEnvironment(recording(), slots).start(heavy, heavy.manifest().arms().get(0));
        order.add("two more free: " + slots.tryAcquire(2).isPresent());
        order.add("one more free: " + slots.tryAcquire(1).map(slot -> {
            slot.close();
            return true;
        }).orElse(false));
        arm.close();

        assertThat(order).containsExactly("start", "two more free: false", "one more free: true", "teardown");
    }

    private LoadedTarget target() {
        ManifestFixtures.writeValidTarget(root, "check-a", "target-one");
        return ManifestFixtures.loadOnly(root, "check-a", "target-one");
    }
}
