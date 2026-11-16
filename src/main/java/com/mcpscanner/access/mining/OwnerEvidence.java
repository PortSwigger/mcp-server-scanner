package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.api.Principal;

import java.util.Optional;

record OwnerEvidence(Optional<String> privateMarker) {

    private static final String ID = "id";

    static final OwnerEvidence NONE = new OwnerEvidence(Optional.empty());

    static OwnerEvidence of(Principal principal) {
        return new OwnerEvidence(principal.privateMarker().filter(marker -> !marker.isBlank()));
    }

    boolean attributes(ReplyField field) {
        return privateMarker.isPresent() && namesRecord(field) && carriesMarker(field.record(), privateMarker.get());
    }

    private static boolean namesRecord(ReplyField field) {
        return ID.equals(Aliases.normalise(field.key())) && field.record().get(field.key()) == field.leaf().value();
    }

    private static boolean carriesMarker(JsonNode node, String marker) {
        if (node.isValueNode()) {
            return node.asText().contains(marker);
        }
        for (JsonNode child : node) {
            if (carriesMarker(child, marker)) {
                return true;
            }
        }
        return false;
    }
}
