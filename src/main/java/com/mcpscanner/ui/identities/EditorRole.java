package com.mcpscanner.ui.identities;

import java.util.Optional;
import java.util.function.Supplier;

enum EditorRole {
    PRIMARY,
    SOLE_PRIMARY,
    COMPARED;

    static EditorRole primaryIn(UsersMode mode) {
        return mode.comparesUsers() ? PRIMARY : SOLE_PRIMARY;
    }

    boolean editsPrimary() {
        return this != COMPARED;
    }

    boolean comparesUsers() {
        return this != SOLE_PRIMARY;
    }

    <P> Optional<P> ifComparing(Supplier<P> part) {
        return comparesUsers() ? Optional.of(part.get()) : Optional.empty();
    }
}
