package com.mcpscanner.access.listing;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

record ToolListings(List<ToolList> realUsers, List<ToolList> synthetic) {

    ToolListings {
        realUsers = List.copyOf(realUsers);
        synthetic = List.copyOf(synthetic);
    }

    Optional<ToolList> listed(String principalId) {
        return Stream.concat(realUsers.stream(), synthetic.stream())
                .filter(list -> list.id().equals(principalId)).findFirst();
    }
}
