package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Set;

record Sighting(JsonNode node, Set<String> aliases, List<String> arguments, String operation, String path,
                Kind kind, boolean ownerAttributed) {

    enum Kind {
        REPLY_FIELD,
        LISTED_RESOURCE,
        LISTED_VARIABLE
    }

    Sighting {
        aliases = Set.copyOf(aliases);
        arguments = List.copyOf(arguments);
    }

    Sighting(JsonNode node, Set<String> aliases, List<String> arguments, String operation, String path, Kind kind) {
        this(node, aliases, arguments, operation, path, kind, false);
    }

    Sighting attributedTo(boolean attributed) {
        return new Sighting(node, aliases, arguments, operation, path, kind, attributed);
    }

    String value() {
        return node.isContainerNode() ? node.toString() : node.asText();
    }

    boolean feedable() {
        return kind != Kind.LISTED_RESOURCE;
    }

    boolean sameAs(Sighting other) {
        return path.equals(other.path) && value().equals(other.value());
    }
}
