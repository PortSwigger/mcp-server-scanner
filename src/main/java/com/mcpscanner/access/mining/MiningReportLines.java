package com.mcpscanner.access.mining;

import com.mcpscanner.identity.MinedValue;
import com.mcpscanner.identity.ValueScope;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class MiningReportLines {

    private MiningReportLines() {
    }

    static MiningReport of(MiningResult result, MiningPlan plan) {
        List<String> warnings = Stream.concat(result.warnings().stream(),
                        result.identities().stream().flatMap(mining -> mining.warnings().stream()))
                .map(warning -> line(warning, plan)).distinct().toList();
        return new MiningReport(result.stop(), warnings, count(result, plan, MinedValue::isOwned),
                count(result, plan, value -> value.scope() == ValueScope.SHARED), usersWithoutIds(result));
    }

    private static Set<String> usersWithoutIds(MiningResult result) {
        return result.identities().stream().flatMap(mining -> mining.warnings().stream())
                .filter(warning -> warning.kind() == MiningWarning.Kind.EMPTY).map(MiningWarning::identityId)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static String line(MiningWarning warning, MiningPlan plan) {
        return warning.identityId() == null ? warning.detail()
                : plan.nameOf(warning.identityId()) + ": " + warning.detail();
    }

    private static int count(MiningResult result, MiningPlan plan,
                              java.util.function.Predicate<MinedValue> counted) {
        return (int) result.identities().stream()
                .filter(mining -> plan.identityIdsByPrincipal().containsKey(mining.identityId()))
                .flatMap(mining -> mining.values().stream()).filter(counted).count();
    }
}
