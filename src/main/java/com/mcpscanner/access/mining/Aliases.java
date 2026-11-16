package com.mcpscanner.access.mining;

import com.mcpscanner.mcp.NameTokens;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

final class Aliases {

    private static final String ID = "id";

    private Aliases() {
    }

    static Set<String> ofLeaf(String key, String parentKey) {
        Set<String> aliases = new LinkedHashSet<>();
        String normalised = normalise(key);
        aliases.add(normalised);
        aliases.add(singular(normalised));
        if (ID.equals(normalised) && parentKey != null) {
            String owner = singular(normalise(parentKey));
            aliases.add(owner + ID);
            aliases.add(owner);
        }
        return Set.copyOf(aliases);
    }

    static Set<String> ofArgument(String name, String ownerName) {
        Set<String> aliases = new LinkedHashSet<>();
        String normalised = normalise(name);
        aliases.add(normalised);
        if (ID.equals(normalised)) {
            aliases.addAll(ofSubject(ownerName));
        }
        return Set.copyOf(aliases);
    }

    static Set<String> ofSubject(String name) {
        Set<String> aliases = new LinkedHashSet<>();
        NameTokens.of(name).forEach(token -> aliases.add(singular(token) + ID));
        return Set.copyOf(aliases);
    }

    static String normalise(String key) {
        return key.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private static String singular(String word) {
        if (word.endsWith("ies") && word.length() > 3) {
            return word.substring(0, word.length() - 3) + "y";
        }
        return word.endsWith("s") && !word.endsWith("ss") ? word.substring(0, word.length() - 1) : word;
    }
}
