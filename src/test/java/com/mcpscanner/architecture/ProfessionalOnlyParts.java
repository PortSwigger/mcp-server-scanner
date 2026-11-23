package com.mcpscanner.architecture;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.identity.discovery.IdentityDiscoveryService;
import com.tngtech.archunit.core.domain.AccessTarget;
import com.tngtech.archunit.core.domain.Dependency;
import com.tngtech.archunit.core.domain.JavaAccess;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaCodeUnit;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;

import java.util.Set;
import java.util.stream.Stream;

final class ProfessionalOnlyParts {

    private static final Set<String> PROFESSIONAL_ONLY_PACKAGES = Set.of(
            "com.mcpscanner.engine", "com.mcpscanner.access", "com.mcpscanner.signedin",
            "burp.api.montoya.collaborator");

    private static final Set<String> PROFESSIONAL_ONLY_API_METHODS = Set.of("scanner", "collaborator", "siteMap");

    private static final Set<String> PROFESSIONAL_ONLY_CONSTRUCTIONS = Set.of(
            CollaboratorWatch.class.getName(), IdentityDiscoveryService.class.getName());

    private ProfessionalOnlyParts() {
    }

    static ArchCondition<JavaClass> reachedByClass() {
        return new ArchCondition<>("reach a Professional-only part") {
            @Override
            public void check(JavaClass javaClass, ConditionEvents events) {
                javaClass.getAccessesFromSelf().stream()
                        .filter(ProfessionalOnlyParts::isProfessionalOnly)
                        .forEach(access -> events.add(SimpleConditionEvent.satisfied(javaClass, access.getDescription())));
                javaClass.getDirectDependenciesFromSelf().stream()
                        .filter(dependency -> isProfessionalOnly(dependency.getTargetClass()))
                        .map(Dependency::getDescription)
                        .forEach(description -> events.add(SimpleConditionEvent.satisfied(javaClass, description)));
            }
        };
    }

    static ArchCondition<JavaCodeUnit> reachedByCodeUnit() {
        return new ArchCondition<>("reach a Professional-only part") {
            @Override
            public void check(JavaCodeUnit codeUnit, ConditionEvents events) {
                codeUnit.getAccessesFromSelf().stream()
                        .filter(ProfessionalOnlyParts::isProfessionalOnly)
                        .forEach(access -> events.add(SimpleConditionEvent.satisfied(codeUnit, access.getDescription())));
                signatureTypes(codeUnit)
                        .filter(ProfessionalOnlyParts::isProfessionalOnly)
                        .forEach(type -> events.add(SimpleConditionEvent.satisfied(codeUnit,
                                codeUnit.getFullName() + " names " + type.getName())));
            }
        };
    }

    private static Stream<JavaClass> signatureTypes(JavaCodeUnit codeUnit) {
        return Stream.concat(codeUnit.getRawParameterTypes().stream(), Stream.of(codeUnit.getRawReturnType()));
    }

    private static boolean isProfessionalOnly(JavaAccess<?> access) {
        AccessTarget target = access.getTarget();
        JavaClass owner = target.getOwner();
        return isProfessionalOnly(owner)
                || owner.isEquivalentTo(MontoyaApi.class) && PROFESSIONAL_ONLY_API_METHODS.contains(target.getName())
                || target instanceof AccessTarget.ConstructorCallTarget
                && PROFESSIONAL_ONLY_CONSTRUCTIONS.contains(owner.getName());
    }

    private static boolean isProfessionalOnly(JavaClass type) {
        JavaClass base = type.getBaseComponentType();
        return PROFESSIONAL_ONLY_PACKAGES.stream().anyMatch(prefix ->
                base.getPackageName().equals(prefix) || base.getPackageName().startsWith(prefix + "."));
    }
}
