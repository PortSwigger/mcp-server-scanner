package com.mcpscanner.automation;

import com.mcpscanner.access.AccessRow;

import java.util.List;
import java.util.function.Supplier;

public record CheckAccessSteps(Runnable awaitListings, Runnable mineEveryUser, Supplier<List<AccessRow>> rows,
                               CheckAccessStart checkAccess) {
}
