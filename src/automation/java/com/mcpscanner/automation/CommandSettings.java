package com.mcpscanner.automation;

import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.registry.ManagedCheck;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

public final class CommandSettings {

    private final ScanCheckRegistry registry;
    private final ScanCheckSettings checkSettings;
    private final Consumer<Boolean> builtInDiversion;

    public CommandSettings(ScanCheckRegistry registry, ScanCheckSettings checkSettings,
                           Consumer<Boolean> builtInDiversion) {
        this.registry = registry;
        this.checkSettings = checkSettings;
        this.builtInDiversion = builtInDiversion;
    }

    void apply(ScanAllCommand command) {
        enableOnly(command);
        builtInDiversion.accept(command.divertBuiltInChecks());
    }

    private void enableOnly(ScanAllCommand command) {
        Set<String> unknown = new HashSet<>(command.checks());
        unknown.remove(ScanAllCommand.EVERY_CHECK);
        for (ManagedCheck check : registry.all()) {
            CheckDescriptor descriptor = check.descriptor();
            unknown.remove(descriptor.id());
            checkSettings.setEnabled(descriptor.id(), command.enables(descriptor.id()));
        }
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException("Unknown checks " + unknown);
        }
    }
}
