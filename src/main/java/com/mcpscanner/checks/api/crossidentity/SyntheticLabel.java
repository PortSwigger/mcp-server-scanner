package com.mcpscanner.checks.api.crossidentity;

import com.mcpscanner.checks.api.Principal;

import java.util.Arrays;
import java.util.Optional;

public enum SyntheticLabel {
    NO_CREDENTIAL(Principal.ANONYMOUS_ID, Principal.ANONYMOUS_NAME, "no credentials sent", "Without credentials"),
    FAKE_TOKEN(Principal.FAKE_TOKEN_ID, Principal.FAKE_TOKEN_NAME, "an invalid token the server never issued",
            "With the fake token");

    public static final String ALWAYS_COMPARED = Principal.ANONYMOUS_NAME + " and a " + Principal.FAKE_TOKEN_NAME;

    private final String principalId;
    private final String label;
    private final String explanation;
    private final String withThe;

    SyntheticLabel(String principalId, String label, String explanation, String withThe) {
        this.principalId = principalId;
        this.label = label;
        this.explanation = explanation;
        this.withThe = withThe;
    }

    public static Optional<SyntheticLabel> of(String principalId) {
        return Arrays.stream(values()).filter(each -> each.principalId.equals(principalId)).findFirst();
    }

    public static String labelOf(Principal principal) {
        return of(principal.id()).map(SyntheticLabel::label).orElse(principal.name());
    }

    public static String alongside(String comparedUsers) {
        return comparedUsers + Arrays.stream(values()).map(each -> " + " + each.label).reduce("", String::concat);
    }

    public String principalId() {
        return principalId;
    }

    public String label() {
        return label;
    }

    public String described() {
        return label + " (" + explanation + ")";
    }

    public String withThe() {
        return withThe;
    }
}
