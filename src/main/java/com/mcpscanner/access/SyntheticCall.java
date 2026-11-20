package com.mcpscanner.access;

import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.OperationReply;

public record SyntheticCall(AccessItemKey item, Principal principal, AccessOutcome outcome, OperationReply reply) {
}
