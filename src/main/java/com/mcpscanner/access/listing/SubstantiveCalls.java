package com.mcpscanner.access.listing;

import com.mcpscanner.access.SyntheticCall;
import com.mcpscanner.access.SyntheticCallLog;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.Principal;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

final class SubstantiveCalls {

    private final SyntheticCallLog log;

    SubstantiveCalls(SyntheticCallLog log) {
        this.log = log;
    }

    List<SyntheticCall> of(Principal principal, Collection<String> tools) {
        return tools.stream()
                .map(tool -> log.call(new AccessItemKey(AccessItemKey.Kind.TOOL, tool), principal.id()))
                .flatMap(Optional::stream)
                .filter(call -> call.reply() != null && call.reply().substantive())
                .toList();
    }
}
