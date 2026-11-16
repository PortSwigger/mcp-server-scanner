package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CorsSeverityTest {

    @ParameterizedTest
    @CsvSource({
            "NONE, false, HIGH",
            "NONE, true, HIGH",
            "COOKIE, true, HIGH",
            "COOKIE, false, LOW",
            "HEADER, true, LOW",
            "HEADER, false, LOW"})
    void isHighOnlyWhenABrowserCanReadWithoutOrWithItsOwnCredentials(CorsAuth auth, boolean credentialed,
                                                                     AuditIssueSeverity expected) {
        assertThat(CorsSeverity.of(auth, credentialed)).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "''|NONE",
            "Cookie|COOKIE",
            "Authorization|HEADER",
            "Cookie,X-Api-Key|HEADER"})
    void classifiesTheCarriedCredentialHeaders(String carried, CorsAuth expected) {
        List<String> names = carried.isEmpty() ? List.of() : List.of(carried.split(","));
        assertThat(CorsAuth.of(names)).isEqualTo(expected);
    }
}
