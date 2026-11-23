package com.mcpscanner.cvetargets.manifest;

import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.mcp.McpMethods;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

final class IdentitySetupValidator {

    private static final String PREFIX = "identities: ";
    private static final Set<String> RESERVED_IDS = Set.of(IdentitySetup.PRIMARY_CALLER, IdentitySetup.ANONYMOUS_CALLER);
    private static final Set<String> ITEM_METHODS = Set.of(McpMethods.TOOLS_CALL, McpMethods.RESOURCES_READ);

    void check(LoadedTarget target, List<String> violations) {
        IdentitySetup identities = target.manifest().identities();
        checkProvisionScript(target, identities, violations);
        checkProvisionedPrimary(target.manifest(), violations);
        checkOthers(identities.others(), violations);
        checkItems(target.manifest(), violations);
    }

    private static void checkProvisionScript(LoadedTarget target, IdentitySetup identities, List<String> violations) {
        if (identities.provision() != null) {
            TargetScripts.requireInTargetDirectory(target, "identities", identities.provision(), violations);
        }
    }

    private static void checkProvisionedPrimary(TargetManifest manifest, List<String> violations) {
        if (!(manifest.auth().token() instanceof ProvisionedToken)) {
            return;
        }
        if (manifest.identities().provision() == null && !manifest.signedInSession().declared()) {
            violations.add(PREFIX + "a provisioned auth token needs a provision script");
        }
        if (!manifest.auth().headers().isEmpty()) {
            violations.add(PREFIX + "a provisioned auth token takes every primary header from the provision script");
        }
    }

    private static void checkOthers(List<OtherIdentity> others, List<String> violations) {
        Set<String> ids = new HashSet<>();
        for (OtherIdentity other : others) {
            if (RESERVED_IDS.contains(other.id())) {
                violations.add(PREFIX + "id " + other.id() + " is reserved");
            } else if (other.id() == null || !other.id().matches("[a-z0-9][a-z0-9-]*")) {
                violations.add(PREFIX + "id " + other.id() + " must be lower-case letters, digits and hyphens");
            } else if (!ids.add(other.id())) {
                violations.add(PREFIX + "id " + other.id() + " is duplicated");
            }
            if (other.role() == null || other.role() == PrincipalRole.PRIMARY) {
                violations.add(PREFIX + other.id() + " needs role peer, lower or higher");
            }
        }
    }

    private static void checkItems(TargetManifest manifest, List<String> violations) {
        IdentitySetup identities = manifest.identities();
        Set<String> arms = manifest.arms().stream().map(TargetArm::name).collect(Collectors.toSet());
        Set<String> callers = identities.callers().collect(Collectors.toSet());
        Set<String> ids = identities.others().stream().map(OtherIdentity::id).collect(Collectors.toSet());
        for (AccessItem item : identities.items()) {
            if (item.seed() == null || !ITEM_METHODS.contains(item.seed().method())) {
                violations.add(PREFIX + "every item seed must be tools/call or resources/read");
            } else if (item.seed().sentAsIdentity() && !ids.contains(item.seed().asIdentity())) {
                violations.add(PREFIX + "item seed asIdentity " + item.seed().asIdentity() + " is not a declared identity");
            }
            item.groundTruth().forEach((arm, declared) -> checkGroundTruth(arm, declared, arms, callers, violations));
        }
    }

    private static void checkGroundTruth(String arm, Map<String, GroundTruthClass> declared, Set<String> arms,
                                         Set<String> callers, List<String> violations) {
        if (!arms.contains(arm)) {
            violations.add(PREFIX + "ground truth names unknown arm " + arm);
        }
        declared.keySet().stream()
                .filter(caller -> !callers.contains(caller))
                .forEach(caller -> violations.add(PREFIX + "ground truth names unknown caller " + caller));
    }
}
