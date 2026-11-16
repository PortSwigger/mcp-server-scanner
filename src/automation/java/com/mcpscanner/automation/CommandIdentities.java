package com.mcpscanner.automation;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public record CommandIdentities(CommandUser connectAs, List<CommandUser> others, Set<String> confirmedWrites,
                                List<ExpectedAccess> expectations, List<SeedCall> itemSeeds) {

    public static final CommandIdentities NONE = new CommandIdentities(null, null, null, null, null);

    public CommandIdentities {
        others = others == null ? List.of() : List.copyOf(others);
        confirmedWrites = confirmedWrites == null ? Set.of() : Set.copyOf(confirmedWrites);
        expectations = expectations == null ? List.of() : List.copyOf(expectations);
        itemSeeds = itemSeeds == null ? List.of() : List.copyOf(itemSeeds);
    }

    Optional<CommandUser> primaryUser() {
        return Optional.ofNullable(connectAs);
    }
}
