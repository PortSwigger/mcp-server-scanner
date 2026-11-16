package com.mcpscanner.automation;

import com.mcpscanner.identity.IdentityRole;

import java.util.Map;

public record CommandUser(String name, IdentityRole role, CommandAuth auth, String privateMarker,
                          Map<String, String> ownedObjects) {

    public CommandUser {
        role = role == null ? IdentityRole.PEER : role;
        auth = auth == null ? CommandAuth.NONE : auth;
        ownedObjects = ownedObjects == null ? Map.of() : Map.copyOf(ownedObjects);
    }
}
