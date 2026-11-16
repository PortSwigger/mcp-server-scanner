package com.mcpscanner.checks.api;

public enum AccessExpectation {
    SHARED_BY_DESIGN,
    ANY_SIGNED_IN,
    NOT_LOWER,
    HIGHER_ONLY,
    OWNER_ONLY;

    public boolean forbids(PrincipalRole role) {
        return switch (this) {
            case ANY_SIGNED_IN, SHARED_BY_DESIGN -> false;
            case NOT_LOWER -> role == PrincipalRole.LOWER;
            case OWNER_ONLY -> true;
            case HIGHER_ONLY -> role != PrincipalRole.HIGHER;
        };
    }
}
