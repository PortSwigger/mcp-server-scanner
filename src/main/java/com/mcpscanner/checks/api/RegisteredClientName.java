package com.mcpscanner.checks.api;

import java.util.Objects;
import java.util.Optional;

public record RegisteredClientName(Optional<String> value) {

    public static final String UNKNOWN = "the scanner client's registered name is unknown, as for a pre-registered "
            + "client";

    public RegisteredClientName {
        value = Objects.requireNonNull(value, "value must not be null").filter(name -> !name.isBlank());
    }

    public static RegisteredClientName of(String name) {
        return new RegisteredClientName(Optional.ofNullable(name));
    }

    public static RegisteredClientName unknown() {
        return new RegisteredClientName(Optional.empty());
    }
}
