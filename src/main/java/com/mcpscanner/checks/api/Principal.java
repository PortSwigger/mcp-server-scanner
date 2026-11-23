package com.mcpscanner.checks.api;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

public record Principal(
        String id,
        String name,
        PrincipalRole role,
        Supplier<Map<String, String>> credentialHeaders,
        Optional<String> privateMarker,
        OwnedObjects ownedObjects,
        Supplier<Map<String, String>> heldCredentials
) {
    public static final String PRIMARY_ID = "primary";
    public static final String PRIMARY_NAME = "Primary";
    public static final String ANONYMOUS_ID = "anonymous";
    public static final String ANONYMOUS_NAME = "No credential";
    public static final String FAKE_TOKEN_ID = "fake-token";
    public static final String FAKE_TOKEN_NAME = "Fake token";

    public Principal {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(role, "role must not be null");
        Objects.requireNonNull(credentialHeaders, "credentialHeaders must not be null");
        heldCredentials = heldCredentials == null ? credentialHeaders : heldCredentials;
        privateMarker = privateMarker == null ? Optional.empty() : privateMarker;
        ownedObjects = ownedObjects == null ? OwnedObjects.NONE : ownedObjects;
    }

    public Principal(String id, String name, PrincipalRole role, Supplier<Map<String, String>> credentialHeaders,
                     Optional<String> privateMarker, Map<String, String> ownedObjects) {
        this(id, name, role, credentialHeaders, privateMarker, OwnedObjects.entered(ownedObjects), credentialHeaders);
    }

    public boolean sharesCredentialsWith(Principal other) {
        return CredentialHeaders.same(heldCredentials.get(), other.heldCredentials().get());
    }

    public static Principal primary(Supplier<Map<String, String>> credentialHeaders) {
        return new Principal(PRIMARY_ID, PRIMARY_NAME, PrincipalRole.PRIMARY, credentialHeaders,
                Optional.empty(), Map.of());
    }

    public static Principal anonymous() {
        return new Principal(ANONYMOUS_ID, ANONYMOUS_NAME, PrincipalRole.LOWER, Map::of, Optional.empty(), Map.of());
    }

    public static Principal fakeToken(Supplier<Map<String, String>> fabricatedHeaders) {
        return new Principal(FAKE_TOKEN_ID, FAKE_TOKEN_NAME, PrincipalRole.LOWER, fabricatedHeaders, Optional.empty(),
                Map.of());
    }

    public static boolean isAnonymous(String principalId) {
        return ANONYMOUS_ID.equals(principalId);
    }
}
