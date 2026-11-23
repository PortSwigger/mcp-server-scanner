package com.mcpscanner.cvetargets.environment;

import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.TargetArm;

import java.net.URI;

public final class SlotLimitedEnvironment implements TargetEnvironment {

    private final TargetEnvironment delegate;
    private final MachineSlots slots;

    public SlotLimitedEnvironment(TargetEnvironment delegate, MachineSlots slots) {
        this.delegate = delegate;
        this.slots = slots;
    }

    @Override
    public RunningArm start(LoadedTarget target, TargetArm arm) {
        return reserve(target, arm).start();
    }

    @Override
    public ReservedArm reserve(LoadedTarget target, TargetArm arm) {
        ReservedArm reserved = delegate.reserve(target, arm);
        ArmSlot slot = slotFor(target, arm, reserved);
        return new ReservedArm(() -> startHolding(slot, reserved), () -> releaseBoth(slot, reserved));
    }

    private ArmSlot slotFor(LoadedTarget target, TargetArm arm, ReservedArm reserved) {
        try {
            return slots.acquire(target.displayName() + "/" + arm.name(),
                    MachineSlots.slotsFor(target.manifest().footprintMb()));
        } catch (RuntimeException | Error acquireFailure) {
            reserved.close();
            throw acquireFailure;
        }
    }

    private RunningArm startHolding(ArmSlot slot, ReservedArm reserved) {
        try {
            return new SlottedArm(reserved.start(), slot);
        } catch (RuntimeException | Error startFailure) {
            releaseAfter(slot, startFailure);
            throw startFailure;
        }
    }

    private static void releaseBoth(ArmSlot slot, ReservedArm reserved) {
        try (slot) {
            reserved.close();
        }
    }

    private static void releaseAfter(ArmSlot slot, Throwable startFailure) {
        try {
            slot.close();
        } catch (RuntimeException releaseFailure) {
            startFailure.addSuppressed(releaseFailure);
        }
    }

    private record SlottedArm(RunningArm arm, ArmSlot slot) implements RunningArm {

        @Override
        public URI endpoint() {
            return arm.endpoint();
        }

        @Override
        public void close() {
            try (slot) {
                arm.close();
            }
        }
    }
}
