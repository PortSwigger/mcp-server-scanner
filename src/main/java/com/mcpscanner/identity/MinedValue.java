package com.mcpscanner.identity;

import java.util.Objects;

public record MinedValue(String argument, String value, MinedSource source, ValueScope scope) implements OwnedValue {

    public MinedValue {
        Objects.requireNonNull(argument, "argument must not be null");
        Objects.requireNonNull(value, "value must not be null");
        Objects.requireNonNull(source, "source must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
    }

    public boolean isOwned() {
        return scope == ValueScope.PRIVATE || scope == ValueScope.ATTRIBUTED;
    }
}
