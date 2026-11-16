package com.mcpscanner.access.mining;

import com.mcpscanner.scan.UriTemplateExpansion;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

final class CallPlanner {

    private static final int LISTED_RESOURCE_SLOTS = 1;

    private final MiningCatalog catalog;
    private final ToolGate gate;

    CallPlanner(MiningCatalog catalog, ToolGate gate) {
        this.catalog = catalog;
        this.gate = gate;
    }

    List<MiningCall> firstPass() {
        return Stream.of(
                        callableTools().map(tool -> new MiningCall.ToolCall(tool.tool(), Map.of())),
                        catalog.inventory().resources().stream().map(resource -> new MiningCall.ResourceRead(resource.uri())),
                        Stream.of(new MiningCall.ResourceListing()),
                        catalog.inventory().prompts().stream().map(MiningCall.PromptGet::new))
                .<MiningCall>flatMap(calls -> calls)
                .toList();
    }

    int mostRequests(MiningSettings settings) {
        long firstPass = callableTools().count() + catalog.inventory().resources().size()
                + catalog.inventory().prompts().size() + settings.listPages();
        long slots = callableTools().mapToLong(tool -> tool.slots().size()).sum()
                + catalog.templates().stream().mapToLong(template -> template.slots().size()).sum();
        long fedPasses = (long) (settings.passes() - 1) * settings.valuesPerArgument() * (slots + LISTED_RESOURCE_SLOTS);
        return (int) Math.min(Integer.MAX_VALUE, (firstPass + fedPasses) * StableExchange.MOST_SENDS_PER_CALL);
    }

    List<MiningCall> fedPass(IdentitySightings sightings) {
        return Stream.of(
                        callableTools().flatMap(tool -> fedToolCalls(tool, sightings)),
                        catalog.templates().stream().flatMap(template -> fedTemplateReads(template, sightings)),
                        sightings.listedResources().stream().map(MiningCall.ResourceRead::new))
                .<MiningCall>flatMap(calls -> calls)
                .toList();
    }

    private Stream<ToolArguments> callableTools() {
        return catalog.tools().stream().filter(tool -> gate.mayCall(tool.tool()));
    }

    private static Stream<MiningCall> fedToolCalls(ToolArguments tool, IdentitySightings sightings) {
        return tool.slots().stream().flatMap(slot -> sightings.feedableFor(slot).stream()
                .map(sighting -> new MiningCall.ToolCall(tool.tool(),
                        Map.of(slot.name(), slot.render(sighting.value())))));
    }

    private static Stream<MiningCall> fedTemplateReads(TemplateArguments template, IdentitySightings sightings) {
        return template.slots().stream().flatMap(slot -> sightings.feedableFor(slot).stream()
                .map(sighting -> new MiningCall.ResourceRead(UriTemplateExpansion.expandWith(
                        template.uriTemplate(), Map.of(slot.name(), sighting.value())))));
    }
}
