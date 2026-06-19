package com.mcpscanner.auth;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Mutable, thread-safe holder for the auth strategy that active checks should
 * use against the configured MCP server. Defaults to {@link NoAuthStrategy}
 * before the user connects. The UI publishes the resolved strategy here before
 * launching a scan so checks like {@code McpActiveAuthBypassCheck} can probe
 * the same credential shape the user configured.
 */
public final class CurrentAuthHolder implements Supplier<AuthStrategy> {

    private final AtomicReference<AuthStrategy> current = new AtomicReference<>(new NoAuthStrategy());

    @Override
    public AuthStrategy get() {
        return current.get();
    }

    public void set(AuthStrategy strategy) {
        current.set(Objects.requireNonNull(strategy, "strategy must not be null"));
    }

    public void clear() {
        current.set(new NoAuthStrategy());
    }
}
