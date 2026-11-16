package com.mcpscanner.access.mining;

import com.mcpscanner.identity.MinedValue;

import java.util.List;

public record IdentityMining(String identityId, List<MinedValue> values, int requestsSent,
                             List<MiningWarning> warnings) {

    public IdentityMining {
        values = List.copyOf(values);
        warnings = List.copyOf(warnings);
    }

    public List<MinedValue> privateValues() {
        return values.stream().filter(value -> value.isOwned()).toList();
    }
}
