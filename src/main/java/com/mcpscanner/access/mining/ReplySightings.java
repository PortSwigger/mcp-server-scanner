package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

final class ReplySightings {

    private static final Set<String> PAGINATION_KEYS = Set.of("cursor", "nextcursor", "prevcursor", "previouscursor",
            "pagetoken", "nextpagetoken", "continuationtoken", "nexttoken", "startcursor", "endcursor", "offset",
            "limit", "page", "pagesize", "perpage", "pagenumber", "total", "totalcount");
    private static final String WRAPPED_RESULT = "result";
    private static final String ID = "id";

    private final MiningCatalog catalog;
    private final ListedResources listings;

    ReplySightings(MiningCatalog catalog) {
        this.catalog = catalog;
        this.listings = new ListedResources(catalog);
    }

    List<Sighting> stable(MiningCall call, MiningReply first, MiningReply second, OwnerEvidence owner) {
        List<Sighting> repeated = of(call, second, owner);
        return of(call, first, owner).stream()
                .filter(sighting -> repeated.stream().anyMatch(sighting::sameAs))
                .toList();
    }

    private List<Sighting> of(MiningCall call, MiningReply reply, OwnerEvidence owner) {
        if (!reply.usable()) {
            return List.of();
        }
        return call instanceof MiningCall.ResourceListing ? listings.sightings(call, reply.result())
                : fields(call, reply, owner);
    }

    private List<Sighting> fields(MiningCall call, MiningReply reply, OwnerEvidence owner) {
        ReplyEchoes echoes = new ReplyEchoes(call, reply.result());
        return Stream.concat(
                        ReplyLeaves.of(reply.result()).stream().filter(field -> IdShape.idShaped(field.leaf().value())
                                && !SecretValue.matches(field.leaf().value())),
                        ReplyArrays.of(reply.result()).stream())
                .filter(field -> !echoes.isNoise(field))
                .filter(field -> !PAGINATION_KEYS.contains(Aliases.normalise(field.key())))
                .filter(field -> !SecretName.matches(field.key()) && !SecretName.matches(field.parentKey()))
                .map(field -> sighting(call, field, owner))
                .filter(sighting -> !sighting.arguments().isEmpty())
                .toList();
    }

    private static Set<String> aliases(MiningCall call, ReplyField field) {
        Set<String> aliases = new HashSet<>(Aliases.ofLeaf(field.key(), field.parentKey()));
        if (call instanceof MiningCall.ToolCall tool && field.parentKey() == null
                && (wrapped(field) || ID.equals(Aliases.normalise(field.key())))) {
            aliases.addAll(Aliases.ofSubject(tool.tool().name()));
        }
        return aliases;
    }

    private static boolean wrapped(ReplyField field) {
        return WRAPPED_RESULT.equals(field.key()) && field.parentKey() == null;
    }

    private Sighting sighting(MiningCall call, ReplyField field, OwnerEvidence owner) {
        Set<String> aliases = aliases(call, field);
        JsonNode value = field.leaf().value();
        return new Sighting(catalog.storedForm(aliases, value), aliases, catalog.argumentsTaking(aliases, value),
                call.operation(), field.path(), Sighting.Kind.REPLY_FIELD, owner.attributes(field));
    }
}
