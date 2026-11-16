package com.mcpscanner.automation;

import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;

public record ExpectedAccess(AccessItemKey item, AccessExpectation expectation) {
}
