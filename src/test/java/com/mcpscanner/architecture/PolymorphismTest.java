package com.mcpscanner.architecture;

import com.tngtech.archunit.core.domain.InstanceofCheck;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaCodeUnit;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.DoNotIncludeTests.class)
public class PolymorphismTest {

    private static final String OAUTH_STRATEGY_FQN = "com.mcpscanner.auth.OAuthAuthCodeStrategy";

    @ArchTest
    static final ArchRule oauth_strategy_not_checked_via_instanceof_outside_auth =
            noClasses().that().resideOutsideOfPackage("com.mcpscanner.auth..")
                    .should(performInstanceofCheckAgainst(OAUTH_STRATEGY_FQN))
                    .because("AuthStrategy is the polymorphic seam. An `instanceof OAuthAuthCodeStrategy` outside "
                            + "auth/ would betray that some caller is reaching for OAuth-specific behaviour through "
                            + "a runtime type test instead of adding a method to AuthStrategy — exactly the "
                            + "smell the Wave 3A refactor removed.");

    private static ArchCondition<JavaClass> performInstanceofCheckAgainst(String targetFqn) {
        return new ArchCondition<>("perform instanceof check against " + targetFqn) {
            @Override
            public void check(JavaClass javaClass, ConditionEvents events) {
                for (JavaCodeUnit codeUnit : javaClass.getCodeUnits()) {
                    for (InstanceofCheck instanceofCheck : codeUnit.getInstanceofChecks()) {
                        if (instanceofCheck.getRawType().getFullName().equals(targetFqn)) {
                            events.add(SimpleConditionEvent.satisfied(javaClass,
                                    String.format("%s performs instanceof check against %s at %s:%d",
                                            codeUnit.getFullName(),
                                            targetFqn,
                                            instanceofCheck.getSourceCodeLocation().getSourceFileName(),
                                            instanceofCheck.getSourceCodeLocation().getLineNumber())));
                        }
                    }
                }
            }
        };
    }
}
