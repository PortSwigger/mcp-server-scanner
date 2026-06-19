package com.mcpscanner.checks;

@FunctionalInterface
interface ArgumentHeuristic {
    boolean matches(String argumentName, String description);
}
