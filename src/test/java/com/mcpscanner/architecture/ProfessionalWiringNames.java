package com.mcpscanner.architecture;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.AccessTarget;
import com.tngtech.archunit.core.domain.JavaAccess;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaCodeUnit;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;

import java.util.stream.Stream;

final class ProfessionalWiringNames {

    private static final String CONSTRUCTOR = "<init>";

    private ProfessionalWiringNames() {
    }

    static ArchCondition<JavaCodeUnit> otherThanThroughTheGate(String gateOwner, String gate,
                                                                DescribedPredicate<JavaClass> professionalWiring) {
        return new ArchCondition<>("name Professional wiring other than through " + gateOwner + "." + gate) {
            @Override
            public void check(JavaCodeUnit codeUnit, ConditionEvents events) {
                codeUnit.getAccessesFromSelf().stream()
                        .filter(access -> professionalWiring.test(access.getTargetOwner()))
                        .filter(access -> !isGatedOrInstanceUse(access, gateOwner, gate))
                        .forEach(access -> events.add(SimpleConditionEvent.satisfied(codeUnit,
                                access.getDescription())));
                signatureTypes(codeUnit)
                        .filter(professionalWiring)
                        .filter(type -> !type.getName().equals(gateOwner))
                        .forEach(type -> events.add(SimpleConditionEvent.satisfied(codeUnit,
                                codeUnit.getFullName() + " names " + type.getName())));
            }
        };
    }

    static ArchCondition<JavaCodeUnit> call(String owner, String method) {
        return new ArchCondition<>("call " + owner + "." + method + "()") {
            @Override
            public void check(JavaCodeUnit codeUnit, ConditionEvents events) {
                boolean calls = codeUnit.getMethodCallsFromSelf().stream().anyMatch(call ->
                        call.getTargetOwner().getName().equals(owner) && call.getName().equals(method));
                events.add(new SimpleConditionEvent(codeUnit, calls,
                        codeUnit.getFullName() + (calls ? " calls " : " does not call ") + owner + "." + method));
            }
        };
    }

    private static boolean isGatedOrInstanceUse(JavaAccess<?> access, String gateOwner, String gate) {
        AccessTarget target = access.getTarget();
        if (!access.getTargetOwner().getName().equals(gateOwner)) {
            return false;
        }
        return target.getName().equals(gate) || !target.getName().equals(CONSTRUCTOR) && !isStatic(target);
    }

    private static boolean isStatic(AccessTarget target) {
        return target.resolveMember().map(member -> member.getModifiers().contains(JavaModifier.STATIC))
                .orElse(true);
    }

    private static Stream<JavaClass> signatureTypes(JavaCodeUnit codeUnit) {
        return Stream.concat(codeUnit.getRawParameterTypes().stream(), Stream.of(codeUnit.getRawReturnType()));
    }
}
