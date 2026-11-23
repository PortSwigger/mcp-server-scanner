package com.mcpscanner.cvetargets.shared;

import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.ReadinessSpec;
import com.mcpscanner.cvetargets.manifest.SeedRequest;
import com.mcpscanner.cvetargets.manifest.TargetArm;
import com.mcpscanner.cvetargets.manifest.TargetManifest;

import java.util.List;
import java.util.function.ToIntFunction;

public record SharedTargetArm(List<ManifestArm> members) {

    public SharedTargetArm {
        if (members.isEmpty()) {
            throw new IllegalArgumentException("a shared target arm needs at least one manifest arm");
        }
        members = List.copyOf(members);
    }

    public ManifestArm lead() {
        return members.get(0);
    }

    public TargetArm arm() {
        return lead().arm();
    }

    public LoadedTarget runnable() {
        TargetManifest lead = lead().target().manifest();
        return new LoadedTarget(lead().target().directory(), new TargetManifest(lead.schemaVersion(), lead.id(),
                lead.check(), lead.product(), lead.advisories(), lead.source(), lead.benign(), lead.compose(),
                lead.auth(), new ReadinessSpec(lead.readiness().probe(), largest(m -> m.readiness().timeoutSeconds()),
                        lead.readiness().call()),
                largest(TargetManifest::readTimeoutSeconds), largest(TargetManifest::armTimeoutSeconds),
                largest(TargetManifest::footprintMb), largest(TargetManifest::maxCatalogItems), everySeed(),
                lead.identities(), List.of(arm()), lead.notes(), lead.smoke(), lead.checkAccess(), lead.downloads(),
                lead.signedInSession()));
    }

    private int largest(ToIntFunction<TargetManifest> limit) {
        return members.stream().map(member -> member.target().manifest()).mapToInt(limit).max().orElseThrow();
    }

    private List<SeedRequest> everySeed() {
        return members.stream().flatMap(member -> member.target().manifest().seeds().stream()).distinct().toList();
    }
}
