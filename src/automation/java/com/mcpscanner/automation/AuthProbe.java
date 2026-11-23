package com.mcpscanner.automation;

import com.mcpscanner.auth.oauth.discovery.AuthRequirement;

import java.net.URI;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongSupplier;

public final class AuthProbe {

    private final Consumer<Boolean> networkingSetting;
    private final Function<URI, AuthRequirement> requirementProbe;
    private final LongSupplier nanoClock;

    public AuthProbe(Consumer<Boolean> networkingSetting, Function<URI, AuthRequirement> requirementProbe) {
        this(networkingSetting, requirementProbe, System::nanoTime);
    }

    AuthProbe(Consumer<Boolean> networkingSetting, Function<URI, AuthRequirement> requirementProbe,
              LongSupplier nanoClock) {
        this.networkingSetting = networkingSetting;
        this.requirementProbe = requirementProbe;
        this.nanoClock = nanoClock;
    }

    public AuthProbeReport run(AuthProbeCommand command) {
        networkingSetting.accept(command.useBurpNetworking());
        long started = nanoClock.getAsLong();
        AuthRequirement requirement = requirementProbe.apply(URI.create(command.url()));
        long elapsed = TimeUnit.NANOSECONDS.toMillis(nanoClock.getAsLong() - started);
        return new AuthProbeReport(requirement.getClass().getSimpleName(), requirement.toString(), elapsed);
    }
}
