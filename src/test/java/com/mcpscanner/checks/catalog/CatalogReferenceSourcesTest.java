package com.mcpscanner.checks.catalog;

import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class CatalogReferenceSourcesTest {

    private static final Pattern EXCLUDED_SOURCE = Pattern.compile(
            "github\\.com/advisories"
                    + "|/security/advisories/"
                    + "|GHSA-"
                    + "|CVE-\\d{4}-\\d+"
                    + "|nvd\\.nist\\.gov"
                    + "|(^|[/.])cve\\.org"
                    + "|cve\\.mitre\\.org"
                    + "|owasp\\.org",
            Pattern.CASE_INSENSITIVE);

    @Test
    void noCheckCitesAnAdvisoryCveOrOwaspSource() {
        assertThat(allReferences()).isNotEmpty().noneMatch(reference -> EXCLUDED_SOURCE.matcher(reference).find());
    }

    @Test
    void excludedSourcePatternCatchesEachExcludedDomain() {
        assertThat(List.of(
                "https://github.com/advisories/GHSA-pw9m-5jxm-xr6h",
                "https://github.com/org/repo/security/advisories/GHSA-9h52-p55h-vw2f",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-53110",
                "https://www.cve.org/CVERecord?id=CVE-2025-5273",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-5273",
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"))
                .allMatch(reference -> EXCLUDED_SOURCE.matcher(reference).find());
    }

    private static List<String> allReferences() {
        return CheckCatalog.discover(CheckServices.standalone()).all().stream()
                .map(McpCheck::descriptor)
                .flatMap(descriptor -> descriptor.references().stream())
                .toList();
    }
}
