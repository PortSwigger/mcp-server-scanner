package com.mcpscanner.cvetargets.identities;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.cvetargets.manifest.IdentitySetup;
import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.OtherIdentity;
import com.mcpscanner.cvetargets.manifest.PrimaryIdentity;
import com.mcpscanner.cvetargets.manifest.SeedRequest;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

public final class ArmIdentities implements Supplier<PrincipalRoster>, PrincipalListings {

    private final LoadedTarget target;
    private final String armName;
    private final AuthStrategy primaryAuth;
    private final IdentityScripts scripts;
    private final RecordingAccessLedger ledger;
    private final ArmSignedInConsent signedInConsent = new ArmSignedInConsent();
    private volatile Map<String, ProvisionedIdentity> provisioned = Map.of();
    private volatile ProvisionedSignedInSession signedInSession;
    private volatile ArmSetupReport report;

    public ArmIdentities(LoadedTarget target, String armName, AuthStrategy primaryAuth, IdentityScripts scripts) {
        this.target = target;
        this.armName = armName;
        this.primaryAuth = primaryAuth;
        this.scripts = scripts;
        this.ledger = RecordingAccessLedger.declaredBy(setup());
    }

    public static ArmIdentities none() {
        return new ArmIdentities(null, null, null, null);
    }

    public void provision(URI endpoint, Duration timeout) {
        provisionIdentities(endpoint, timeout);
        provisionSignedInSession(endpoint, timeout);
    }

    public SignedInConsent signedInConsent() {
        return signedInSessionDeclared() ? signedInConsent : SignedInConsent.OPTED_OUT;
    }

    public Optional<ProvisionedSignedInSession> signedInSession() {
        return Optional.ofNullable(signedInSession);
    }

    private void provisionIdentities(URI endpoint, Duration timeout) {
        if (setup().provision() == null) {
            return;
        }
        provisioned = Map.copyOf(scripts.provision().run(target, endpoint, timeout));
        providePrimaryHeaders(provisionedFor(Principal.PRIMARY_ID).headers());
    }

    private void provisionSignedInSession(URI endpoint, Duration timeout) {
        if (!signedInSessionDeclared()) {
            return;
        }
        ProvisionedSignedInSession session = scripts.signedIn().run(target, endpoint, timeout);
        signedInSession = session;
        signedInConsent.provide(endpoint, session);
        if (!session.headers().isEmpty()) {
            providePrimaryHeaders(session.headers());
        }
    }

    private void providePrimaryHeaders(Map<String, String> headers) {
        if (primaryAuth instanceof ProvisionedCredential credential) {
            credential.provide(headers);
        }
    }

    private boolean signedInSessionDeclared() {
        return target != null && target.manifest().signedInSession().declared();
    }

    public void bind(URI endpoint) {
        if (!declared()) {
            return;
        }
        report = scripts.setup().run(target, armName, endpoint, primaryAuth.headers(), provisioned);
        if (!report.contradictions().isEmpty()) {
            throw new IllegalStateException("ground truth contradicts the manifest: "
                    + String.join("; ", report.contradictions()));
        }
    }

    public List<SeedRequest> routed(List<SeedRequest> seeds) {
        return seeds.stream().map(this::routed).toList();
    }

    private SeedRequest routed(SeedRequest seed) {
        if (!seed.sentAsIdentity()) {
            return seed;
        }
        Principal identity = get().compared().stream()
                .filter(principal -> principal.id().equals(seed.asIdentity()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("seed names unknown identity " + seed.asIdentity()));
        return seed.routedBy(new IdentitySeedRouting(identity.id(), identity.credentialHeaders(),
                primaryAuth.contributedHeaderNames()));
    }

    public RecordingAccessLedger ledger() {
        return ledger;
    }

    public Optional<IdentityEvidence> evidence() {
        ArmSetupReport bound = report;
        return bound == null ? Optional.empty()
                : Optional.of(new IdentityEvidence(bound.groundTruth(), ledger.records()));
    }

    @Override
    public Optional<Boolean> lists(String principalId, AccessItemKey item) {
        ArmSetupReport bound = report;
        return bound == null ? Optional.empty()
                : Optional.ofNullable(bound.listings().get(principalId)).flatMap(listing -> listing.lists(item));
    }

    @Override
    public PrincipalRoster get() {
        ArmSetupReport bound = report;
        if (bound == null) {
            return PrincipalRoster.empty();
        }
        return PrincipalRoster.of(primary(), setup().others().stream()
                .map(other -> principal(other, provisionedFor(other.id())))
                .toList());
    }

    private Principal primary() {
        PrimaryIdentity primary = setup().primary();
        return new Principal(Principal.PRIMARY_ID, primary.name(), PrincipalRole.PRIMARY, primaryAuth::headers,
                Optional.ofNullable(primary.privateMarker()),
                merged(primary.ownedObjects(), provisionedFor(Principal.PRIMARY_ID).ownedObjects()));
    }

    private ProvisionedIdentity provisionedFor(String id) {
        return provisioned.getOrDefault(id, new ProvisionedIdentity(null, null));
    }

    private static Map<String, String> merged(Map<String, String> declared, Map<String, String> provisioned) {
        Map<String, String> merged = new LinkedHashMap<>(declared);
        merged.putAll(provisioned);
        return merged;
    }

    private static Principal principal(OtherIdentity other, ProvisionedIdentity provisioned) {
        Map<String, String> credentials = Map.copyOf(merged(other.headers(), provisioned.headers()));
        return new Principal(other.id(), other.name(), other.role(), () -> credentials,
                Optional.ofNullable(other.privateMarker()), merged(other.ownedObjects(), provisioned.ownedObjects()));
    }

    private boolean declared() {
        return setup().declared();
    }

    private IdentitySetup setup() {
        return target == null ? IdentitySetup.none() : target.manifest().identities();
    }
}
