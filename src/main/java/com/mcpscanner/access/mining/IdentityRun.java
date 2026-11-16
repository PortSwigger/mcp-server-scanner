package com.mcpscanner.access.mining;

import java.util.Optional;

record IdentityRun(String identityId, IdentitySightings sightings, int requestsSent,
                   Optional<MiningWarning> limitWarning, MiningStop stop) {
}
