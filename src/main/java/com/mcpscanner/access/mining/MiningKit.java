package com.mcpscanner.access.mining;

record MiningKit(MiningSender sender, CallPlanner planner, ReplySightings replySightings, MiningControl control,
                 MiningHalt halt) {
}
