package com.mcpscanner.access;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.access.mining.MinedValueRule;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.MinedArguments;
import com.mcpscanner.scan.OwnedArguments;
import com.mcpscanner.scan.OwnerArgumentSource;
import com.mcpscanner.scan.RequiredArguments;
import com.mcpscanner.scan.ScanTarget;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

public final class OwnerRequests {

    private final Function<ScanTarget, HttpRequest> primaryRequests;
    private final IdentityRequests identities;
    private final MinedValueRule minedValues;

    public OwnerRequests(Function<ScanTarget, HttpRequest> primaryRequests, IdentityRequests identities) {
        this(primaryRequests, identities, MinedValueRule.READ_TOOLS_ONLY);
    }

    public OwnerRequests(Function<ScanTarget, HttpRequest> primaryRequests, IdentityRequests identities,
                         MinedValueRule minedValues) {
        this.primaryRequests = primaryRequests;
        this.identities = identities;
        this.minedValues = minedValues;
    }

    public HttpRequest forOwner(AccessRow row) {
        return identities.routed(row.owner(), primaryRequest(row));
    }

    public HttpRequest as(AccessRow row, Principal principal) {
        return row.ownedBy(principal) ? forOwner(row) : identities.as(principal, primaryRequest(row));
    }

    public List<McpToolDefinition> ownersTools(List<AccessRow> rows) {
        return rows.stream().flatMap(row -> row.item().tool().map(tool -> ownersTool(row, tool)).stream()).toList();
    }

    public MinedArguments minedArguments(List<AccessRow> rows) {
        Map<String, Set<String>> byTool = new HashMap<>();
        rows.forEach(row -> row.item().tool().ifPresent(tool ->
                byTool.put(tool.name(), argumentsOf(row).minedArgumentsFor(tool))));
        return new MinedArguments(byTool);
    }

    private HttpRequest primaryRequest(AccessRow row) {
        return primaryRequests.apply(ownersTarget(row));
    }

    private ScanTarget ownersTarget(AccessRow row) {
        ScanTarget target = row.item().target();
        return target instanceof ScanTarget.Tool tool ? new ScanTarget.Tool(ownersTool(row, tool.tool())) : target;
    }

    private McpToolDefinition ownersTool(AccessRow row, McpToolDefinition tool) {
        return RequiredArguments.only(OwnedArguments.apply(tool, argumentsOf(row).forTool(tool)));
    }

    private OwnerArgumentSource argumentsOf(AccessRow row) {
        return minedValues.argumentsOf(() -> row.owner().ownedObjects());
    }
}
