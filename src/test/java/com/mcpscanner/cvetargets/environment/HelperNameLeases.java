package com.mcpscanner.cvetargets.environment;

import com.mcpscanner.cvetargets.run.ArmSchedule;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

final class HelperNameLeases {

    private final Set<String> held = new HashSet<>();
    private final Consumer<String> log;

    HelperNameLeases(Consumer<String> log) {
        this.log = log;
    }

    Lease acquire(String armLabel, Set<String> names) {
        if (!tookFree(armLabel, names)) {
            ArmSchedule.waitOutsideItsSlot(() -> takeOnceReleased(names));
        }
        return new Lease(Set.copyOf(names));
    }

    private synchronized boolean tookFree(String armLabel, Set<String> names) {
        if (isAnyHeld(names)) {
            log.accept(armLabel + ": waiting for another arm of this run to tear down, because it holds helper"
                    + " service name(s) " + heldAmong(names) + " on the shared network");
            return false;
        }
        held.addAll(names);
        return true;
    }

    private synchronized void takeOnceReleased(Set<String> names) {
        awaitRelease(names);
        held.addAll(names);
    }

    private boolean isAnyHeld(Set<String> names) {
        return !Collections.disjoint(held, names);
    }

    private Set<String> heldAmong(Set<String> names) {
        Set<String> conflicting = new TreeSet<>(names);
        conflicting.retainAll(held);
        return conflicting;
    }

    private void awaitRelease(Set<String> names) {
        while (isAnyHeld(names)) {
            awaitRelease();
        }
    }

    private void awaitRelease() {
        try {
            wait();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while waiting for helper service names", e);
        }
    }

    private synchronized void release(Set<String> names) {
        held.removeAll(names);
        notifyAll();
    }

    final class Lease implements AutoCloseable {

        private final Set<String> names;
        private boolean released;

        private Lease(Set<String> names) {
            this.names = names;
        }

        @Override
        public void close() {
            synchronized (HelperNameLeases.this) {
                if (released) {
                    return;
                }
                released = true;
                release(names);
            }
        }
    }
}
