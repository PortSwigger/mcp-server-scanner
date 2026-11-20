package com.mcpscanner.identity;

import com.mcpscanner.checks.api.crossidentity.SyntheticLabel;

public final class AnonymousComparison {

    private AnonymousComparison() {
    }

    public static String alongside(String comparedUsers) {
        return SyntheticLabel.alongside(comparedUsers);
    }
}
