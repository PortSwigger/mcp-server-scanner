package com.mcpscanner.cvetargets.manifest;

import com.mcpscanner.automation.CatalogLimit;

import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;

public record TargetManifest(
        int schemaVersion,
        String id,
        String check,
        String product,
        List<String> advisories,
        SourceReference source,
        boolean benign,
        String compose,
        AuthSetup auth,
        ReadinessSpec readiness,
        Integer readTimeoutSeconds,
        Integer armTimeoutSeconds,
        Integer footprintMb,
        Integer maxCatalogItems,
        List<SeedRequest> seeds,
        IdentitySetup identities,
        List<TargetArm> arms,
        String notes,
        boolean smoke,
        boolean checkAccess,
        List<Download> downloads,
        SignedInSessionSetup signedInSession,
        boolean startFirst) {

    public static final int CURRENT_SCHEMA_VERSION = 1;
    public static final String DEFAULT_COMPOSE_FILE = "compose.yaml";
    public static final int DEFAULT_READ_TIMEOUT_SECONDS = 10;
    public static final int DEFAULT_ARM_TIMEOUT_SECONDS = 1200;
    public static final int DEFAULT_FOOTPRINT_MB = 512;
    public static final int DEFAULT_MAX_CATALOG_ITEMS = 100;

    public TargetManifest {
        advisories = advisories == null ? List.of() : List.copyOf(advisories);
        seeds = seeds == null ? List.of() : List.copyOf(seeds);
        identities = identities == null ? IdentitySetup.none() : identities;
        arms = arms == null ? List.of() : List.copyOf(arms);
        compose = compose == null ? DEFAULT_COMPOSE_FILE : compose;
        auth = auth == null ? AuthSetup.none() : auth;
        readiness = readiness == null ? ReadinessSpec.defaults() : readiness;
        readTimeoutSeconds = readTimeoutSeconds == null ? DEFAULT_READ_TIMEOUT_SECONDS : readTimeoutSeconds;
        armTimeoutSeconds = armTimeoutSeconds == null ? DEFAULT_ARM_TIMEOUT_SECONDS : armTimeoutSeconds;
        footprintMb = footprintMb == null ? DEFAULT_FOOTPRINT_MB : footprintMb;
        maxCatalogItems = maxCatalogItems == null ? DEFAULT_MAX_CATALOG_ITEMS : maxCatalogItems;
        downloads = downloads == null ? List.of() : List.copyOf(downloads);
        signedInSession = signedInSession == null ? SignedInSessionSetup.none() : signedInSession;
    }

    public TargetManifest(int schemaVersion, String id, String check, String product, List<String> advisories,
                          SourceReference source, boolean benign, String compose, AuthSetup auth,
                          ReadinessSpec readiness, Integer readTimeoutSeconds, Integer armTimeoutSeconds,
                          Integer footprintMb, Integer maxCatalogItems, List<SeedRequest> seeds,
                          IdentitySetup identities, List<TargetArm> arms, String notes, boolean smoke,
                          boolean checkAccess, List<Download> downloads, SignedInSessionSetup signedInSession) {
        this(schemaVersion, id, check, product, advisories, source, benign, compose, auth, readiness,
                readTimeoutSeconds, armTimeoutSeconds, footprintMb, maxCatalogItems, seeds, identities, arms, notes,
                smoke, checkAccess, downloads, signedInSession, false);
    }

    public TargetManifest(int schemaVersion, String id, String check, String product, List<String> advisories,
                          SourceReference source, boolean benign, String compose, AuthSetup auth,
                          ReadinessSpec readiness, Integer readTimeoutSeconds, Integer armTimeoutSeconds,
                          Integer footprintMb, Integer maxCatalogItems, List<SeedRequest> seeds,
                          IdentitySetup identities, List<TargetArm> arms, String notes, boolean smoke,
                          boolean checkAccess, List<Download> downloads) {
        this(schemaVersion, id, check, product, advisories, source, benign, compose, auth, readiness,
                readTimeoutSeconds, armTimeoutSeconds, footprintMb, maxCatalogItems, seeds, identities, arms, notes,
                smoke, checkAccess, downloads, null, false);
    }

    public TargetManifest(int schemaVersion, String id, String check, String product, List<String> advisories,
                          SourceReference source, boolean benign, String compose, AuthSetup auth,
                          ReadinessSpec readiness, Integer readTimeoutSeconds, Integer armTimeoutSeconds,
                          Integer footprintMb, Integer maxCatalogItems, List<SeedRequest> seeds,
                          IdentitySetup identities, List<TargetArm> arms, String notes, boolean smoke,
                          boolean checkAccess) {
        this(schemaVersion, id, check, product, advisories, source, benign, compose, auth, readiness,
                readTimeoutSeconds, armTimeoutSeconds, footprintMb, maxCatalogItems, seeds, identities, arms, notes,
                smoke, checkAccess, List.of());
    }

    public List<SeedRequest> baseSeeds() {
        return Stream.concat(seeds.stream(), identities.itemSeeds().stream()).toList();
    }

    public Duration readTimeout() {
        return Duration.ofSeconds(readTimeoutSeconds);
    }

    public CatalogLimit catalogLimit() {
        return new CatalogLimit(maxCatalogItems);
    }

    public Duration armTimeout() {
        return Duration.ofSeconds(armTimeoutSeconds);
    }
}
