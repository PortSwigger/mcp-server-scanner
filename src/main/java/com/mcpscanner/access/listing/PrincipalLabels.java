package com.mcpscanner.access.listing;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.SyntheticLabel;

import java.util.List;

final class PrincipalLabels {

    private PrincipalLabels() {
    }

    static String describe(Principal principal) {
        return SyntheticLabel.of(principal.id()).map(SyntheticLabel::described).orElseGet(() -> quoted(principal));
    }

    static String label(Principal principal) {
        return SyntheticLabel.labelOf(principal);
    }

    static String names(List<ToolList> lists) {
        return String.join(" and ", lists.stream().map(ToolList::principal).map(PrincipalLabels::quoted).toList());
    }

    private static String quoted(Principal principal) {
        return "\"" + principal.name() + "\"";
    }
}
