package com.mcpscanner.checks;

import com.mcpscanner.checks.ResourceTraversalPayloads.TraversalPayload;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class ResourceTraversalPayloadsTest {

    @Test
    void fixedStillContainsOriginalPasswdAbsoluteUri() {
        assertThat(uris(ResourceTraversalPayloads.fixed())).contains("file:///etc/passwd");
    }

    @Test
    void everyTraversalUriContainsADotDotEscape() {
        assertThat(payloadsOfTier(PathTraversalTier.TRAVERSAL))
                .isNotEmpty()
                .allSatisfy(payload ->
                        assertThat(PathTraversalTierInvariant.hasDotDotEscape(payload.uri()))
                                .as("traversal uri %s must contain a dot-dot escape", payload.uri())
                                .isTrue());
    }

    @Test
    void eachDifferentialFamilyEmitsTheDeepAndShallowLiteralTraversalsUnderOneKey() {
        // Count lock: each differential family emits exactly the small principled {deep, shallow}
        // literal set — two plain TRAVERSAL payloads (../x16 and ../x3) sharing ONE differentialKey so
        // oracle/dedup accounting is unchanged. The shallow companion reaches a raw-prefilter handler
        // that would reject the deep prefix outright.
        Map<String, List<TraversalPayload>> plainByKey = ResourceTraversalPayloads.fixed().stream()
                .filter(payload -> payload.tier() == PathTraversalTier.TRAVERSAL)
                .collect(Collectors.groupingBy(TraversalPayload::differentialKey));

        assertThat(plainByKey).isNotEmpty();
        assertThat(plainByKey.values()).allSatisfy(group -> {
            assertThat(group).hasSize(2);
            assertThat(uris(group)).anySatisfy(uri -> assertThat(uri).contains(deepPrefix()));
            assertThat(uris(group)).anySatisfy(uri -> assertThat(uri).contains(shallowPrefix()));
        });
    }

    @Test
    void everyEncodingBypassUriContainsAnEncodedEscape() {
        assertThat(payloadsOfTier(PathTraversalTier.ENCODING_BYPASS))
                .isNotEmpty()
                .allSatisfy(payload ->
                        assertThat(PathTraversalTierInvariant.hasEncodedEscape(payload.uri()))
                                .as("encoding-bypass uri %s must contain an encoded escape", payload.uri())
                                .isTrue());
    }

    @Test
    void everyEncodingBypassPayloadSharesDifferentialKeyWithAPlainTraversal() {
        Set<String> plainTraversalKeys = payloadsOfTier(PathTraversalTier.TRAVERSAL).stream()
                .map(TraversalPayload::differentialKey)
                .collect(Collectors.toSet());

        assertThat(payloadsOfTier(PathTraversalTier.ENCODING_BYPASS))
                .isNotEmpty()
                .allSatisfy(payload ->
                        assertThat(plainTraversalKeys)
                                .as("encoded twin %s must share a differentialKey with a plain traversal",
                                        payload.uri())
                                .contains(payload.differentialKey()));
    }

    @Test
    void everyAbsoluteUriHasNoDotDotEscape() {
        assertThat(payloadsOfTier(PathTraversalTier.ABSOLUTE))
                .isNotEmpty()
                .allSatisfy(payload ->
                        assertThat(PathTraversalTierInvariant.hasDotDotEscape(payload.uri()))
                                .as("absolute uri %s must not contain a dot-dot escape", payload.uri())
                                .isFalse());
    }

    @Test
    void everyAbsoluteUriContainsNeitherDotDotNorEncodedEscape() {
        // The ABSOLUTE tier is "no escape at all" — it names the target directly (file:///etc/passwd,
        // file:///etc%2Fpasswd). It percent-encodes slashes but never escapes a directory, so it must
        // match neither tier-invariant regex.
        assertThat(payloadsOfTier(PathTraversalTier.ABSOLUTE))
                .isNotEmpty()
                .allSatisfy(payload -> {
                    assertThat(PathTraversalTierInvariant.hasDotDotEscape(payload.uri()))
                            .as("absolute uri %s must not contain a dot-dot escape", payload.uri())
                            .isFalse();
                    assertThat(PathTraversalTierInvariant.hasEncodedEscape(payload.uri()))
                            .as("absolute uri %s must not contain an encoded escape", payload.uri())
                            .isFalse();
                });
    }

    @Test
    void fromStaticUrisDerivesEscapesForFileScheme() {
        List<TraversalPayload> payloads =
                ResourceTraversalPayloads.fromStaticUris(List.of("file:///workspace/readme.txt"));

        assertThat(payloads).isNotEmpty();
        assertThat(payloads)
                .anySatisfy(payload -> assertThat(payload.tier()).isEqualTo(PathTraversalTier.TRAVERSAL))
                .anySatisfy(payload -> assertThat(payload.tier()).isEqualTo(PathTraversalTier.ENCODING_BYPASS));
        // Every derived probe stays on the discovered file:// scheme. The prefix-sibling tier is no
        // longer a content payload here — it is the error-differential probe pair (see
        // prefixSiblingProbe), so fromStaticUris emits only the content-disclosure families.
        assertThat(uris(payloads)).allMatch(uri -> uri.startsWith("file:///"));
        assertThat(payloads).noneSatisfy(payload ->
                assertThat(payload.tier()).isEqualTo(PathTraversalTier.PREFIX_SIBLING));
    }

    @Test
    void fromStaticUrisDerivesNothingForSchemeWithoutFilesystemAuthorityShape() {
        // docs://readme has no ":///"-empty-authority + path-segment shape, so there is no
        // filesystem root to escape from — derive nothing (FP guard for non-file resources).
        assertThat(ResourceTraversalPayloads.fromStaticUris(List.of("docs://readme"))).isEmpty();
    }

    @Test
    void fromStaticUrisDerivesEscapesForCustomFilesystemScheme() {
        // Real file servers and the test-server prefixmatch fixture leak their root on a custom
        // scheme (prefixmatch:///<root>/canary.txt). Root derivation must follow the scheme so the
        // content-disclosure escapes route back to the validator.
        List<TraversalPayload> payloads = ResourceTraversalPayloads.fromStaticUris(
                List.of("prefixmatch:///srv/mcp-lab-res/canary.txt"));

        assertThat(payloads).isNotEmpty();
        assertThat(uris(payloads)).allMatch(uri -> uri.startsWith("prefixmatch:///"));
    }

    @Test
    void fromStaticUrisEmitsVerbatimContentTraversalForSingleSegmentDirectoryRoot() {
        // FN fix (Codex review): a server may list the directory root itself as a single-segment URI
        // (file:///workspace). fileBaseDirectory returns null for that (no parent), but the directory
        // is still a valid VERBATIM base. We must emit the content-disclosure traversal families
        // rooted at the discovered URI verbatim so a naive un-normalized startsWith(full-root) server
        // is reached. Content-probe only (FileSignature-gated) so a sandboxed server fires nothing.
        String root = "file:///workspace";
        List<TraversalPayload> payloads = ResourceTraversalPayloads.fromStaticUris(List.of(root));

        assertThat(payloads)
                .anySatisfy(payload -> assertThat(payload.tier()).isEqualTo(PathTraversalTier.TRAVERSAL))
                .anySatisfy(payload -> assertThat(payload.tier()).isEqualTo(PathTraversalTier.ENCODING_BYPASS));
        assertThat(uris(payloads))
                .anySatisfy(uri -> assertThat(uri)
                        .startsWith(root + "/" + deepPrefix())
                        .endsWith("etc/passwd"));
    }

    @Test
    void fromStaticUrisTreatsSingleSegmentUriAsVerbatimDirectoryBase() {
        // A single-segment URI (file:///readme.txt) has no parent directory to strip, but it is still
        // a valid VERBATIM base — a single-segment root indistinguishable from a directory. It emits
        // content-disclosure traversals rooted at the URI verbatim (FileSignature-gated, FP-safe).
        String root = "file:///readme.txt";
        List<TraversalPayload> payloads = ResourceTraversalPayloads.fromStaticUris(List.of(root));

        assertThat(uris(payloads))
                .isNotEmpty()
                .allMatch(uri -> uri.startsWith(root + "/"));
    }

    @Test
    void fromStaticUrisEmitsAVerbatimBaseTraversalForADirectoryRootResource() {
        // DiggAI shape: the server lists the vault ROOT DIRECTORY itself as the only resource and
        // guards reads with a naive UN-normalized startsWith(full-root). A literal ../ that RETAINS
        // the full discovered root as a string prefix passes the guard but OS-resolves outside it.
        // The stripped-parent base drops the last segment (.obsidian-vault) and fails that guard, so
        // we ALSO emit a family rooted at the discovered URI VERBATIM (treated as a directory).
        String root = "file:///app/data/notes/.obsidian-vault";
        List<TraversalPayload> payloads = ResourceTraversalPayloads.fromStaticUris(List.of(root));

        assertThat(uris(payloads))
                .as("a deep TRAVERSAL payload must retain the full discovered root as a prefix")
                .anySatisfy(uri -> assertThat(uri)
                        .startsWith(root + "/" + deepPrefix())
                        .endsWith("etc/passwd"));
    }

    @Test
    void fromStaticUrisVerbatimBaseAndStrippedParentBaseAreBothCovered() {
        // A file-listing server (resource = a FILE in the root) needs the stripped-parent base; a
        // dir-listing server (resource = the ROOT itself) needs the verbatim base. Both must be
        // emitted so the one check covers the whole "resource = a directory/root" class.
        String root = "file:///app/data/notes/.obsidian-vault";
        List<String> uris = uris(ResourceTraversalPayloads.fromStaticUris(List.of(root)));

        assertThat(uris).anySatisfy(uri ->
                assertThat(uri).startsWith("file:///app/data/notes/" + deepPrefix()));   // stripped-parent
        assertThat(uris).anySatisfy(uri ->
                assertThat(uri).startsWith(root + "/" + deepPrefix()));                  // verbatim
    }

    @Test
    void fromStaticUrisVerbatimBaseEmitsEncodedTwinsToo() {
        // The encoded twins must also be rooted at the verbatim base, so a decode-after-check
        // dir-root server is reachable by the ENCODING_BYPASS tier as well as plain TRAVERSAL.
        String root = "file:///app/data/notes/.obsidian-vault";
        List<TraversalPayload> payloads = ResourceTraversalPayloads.fromStaticUris(List.of(root));

        assertThat(payloads)
                .filteredOn(p -> p.tier() == PathTraversalTier.ENCODING_BYPASS)
                .anySatisfy(p -> assertThat(p.uri()).startsWith(root + "/..%2f"));
    }

    @Test
    void fromStaticUrisEmitsTheDeepAndShallowTraversalsPerBase() {
        // Count lock: a directory-root URI yields TWO bases (stripped-parent + verbatim), each
        // emitting the {deep, shallow} literal set — so four plain TRAVERSAL payloads across two
        // differential keys (one key per base, two prefixes per key).
        List<TraversalPayload> plain = ResourceTraversalPayloads.fromStaticUris(
                        List.of("file:///app/data/notes/.obsidian-vault")).stream()
                .filter(p -> p.tier() == PathTraversalTier.TRAVERSAL)
                .toList();

        assertThat(plain).hasSize(4);
        assertThat(plain).extracting(TraversalPayload::differentialKey).containsOnly(
                plain.stream().map(TraversalPayload::differentialKey).distinct().toArray(String[]::new));
        assertThat(plain.stream().map(TraversalPayload::differentialKey).distinct().toList()).hasSize(2);
        assertThat(uris(plain)).anySatisfy(uri -> assertThat(uri).contains(deepPrefix()));
        assertThat(uris(plain)).anySatisfy(uri -> assertThat(uri).contains(shallowPrefix()));
    }

    @Test
    void fromStaticUrisFileInRootEmitsTheDeepAndShallowTraversalsPerBaseAndNoDuplicateUris() {
        // A file-in-root URI also yields two bases (parent != verbatim); each emits {deep, shallow},
        // so four plain traversals, all distinct URIs.
        List<String> uris = uris(ResourceTraversalPayloads.fromStaticUris(
                List.of("file:///workspace/readme.txt")));
        long plainCount = ResourceTraversalPayloads.fromStaticUris(
                        List.of("file:///workspace/readme.txt")).stream()
                .filter(p -> p.tier() == PathTraversalTier.TRAVERSAL)
                .count();

        assertThat(plainCount).isEqualTo(4);
        assertThat(uris).doesNotHaveDuplicates();
    }

    @Test
    void fromStaticUrisDoesNotDuplicatePayloadUrisAcrossBases() {
        // Both bases are emitted but no two payloads share an identical URI (no redundant probes).
        List<String> uris = uris(ResourceTraversalPayloads.fromStaticUris(
                List.of("file:///app/data/notes/.obsidian-vault")));
        assertThat(uris).doesNotHaveDuplicates();
    }

    @Test
    void fromTemplatesProducesDifferentialFamiliesForSingleVariableFileTemplate() {
        List<TraversalPayload> payloads =
                ResourceTraversalPayloads.fromTemplates(List.of("file:///{path}"));

        assertThat(payloads)
                .anySatisfy(payload -> assertThat(payload.tier()).isEqualTo(PathTraversalTier.TRAVERSAL))
                .anySatisfy(payload -> assertThat(payload.tier()).isEqualTo(PathTraversalTier.ENCODING_BYPASS));
    }

    @Test
    void fromTemplatesIgnoresMultiVariableTemplates() {
        assertThat(ResourceTraversalPayloads.fromTemplates(List.of("file:///{root}/{path}")))
                .isEmpty();
    }

    @Test
    void fromTemplatesProducesDifferentialFamiliesForCustomSchemeTemplate() {
        // Real-world file servers and the test-server fixtures use custom schemes
        // (rooted:///, encoded:///). Template injection must be scheme-agnostic, otherwise
        // those servers are false negatives. The corroborated signature oracle keeps it FP-safe.
        List<TraversalPayload> payloads =
                ResourceTraversalPayloads.fromTemplates(List.of("rooted:///{path}"));

        assertThat(payloads)
                .anySatisfy(payload -> assertThat(payload.tier()).isEqualTo(PathTraversalTier.TRAVERSAL))
                .anySatisfy(payload -> assertThat(payload.tier()).isEqualTo(PathTraversalTier.ENCODING_BYPASS));
        assertThat(uris(payloads)).allMatch(uri -> uri.startsWith("rooted:///"));
    }

    @Test
    void fromTemplatesAlwaysPairsEncodedTwinsWithAPlainTraversalForTheDifferential() {
        // To claim ENCODING_BYPASS the runner must observe the plain ../ NEGATIVE, so every
        // template family must emit both the plain traversal and its encoded twins.
        List<TraversalPayload> payloads =
                ResourceTraversalPayloads.fromTemplates(List.of("encoded:///{path}"));

        Set<String> plainKeys = payloads.stream()
                .filter(p -> p.tier() == PathTraversalTier.TRAVERSAL)
                .map(TraversalPayload::differentialKey)
                .collect(Collectors.toSet());
        assertThat(payloads.stream().filter(p -> p.tier() == PathTraversalTier.ENCODING_BYPASS))
                .isNotEmpty()
                .allSatisfy(p -> assertThat(plainKeys).contains(p.differentialKey()));
    }

    @Test
    void prefixSiblingProbeTargetsAPrefixSharingSiblingOfTheDiscoveredRoot() {
        // CVE-2025-53110: the sibling walks one level up out of the root, then into a directory
        // whose name shares the root's prefix (<root-basename>_mcpscan_...); the deny-control walks
        // up into a clearly-unrelated, non-prefix-sharing directory. Slashes are percent-encoded so
        // both survive single-template-variable routing, and both stay on the discovered scheme.
        ResourceTraversalPayloads.PrefixSiblingProbe probe =
                ResourceTraversalPayloads.prefixSiblingProbe("file:///workspace/readme.txt");

        assertThat(probe).isNotNull();
        assertThat(probe.siblingUri()).startsWith("file:///..%2fworkspace_mcpscan_");
        assertThat(probe.denyControlUri()).startsWith("file:///..%2fmcpscan-nonexistent-");
        assertThat(probe.denyControlUri()).doesNotContain("workspace_mcpscan");
    }

    @Test
    void prefixSiblingProbeReturnsNullForResourceWithNoDerivableRoot() {
        assertThat(ResourceTraversalPayloads.prefixSiblingProbe("docs://readme")).isNull();
        assertThat(ResourceTraversalPayloads.prefixSiblingProbe("file:///readme.txt")).isNull();
    }

    private static String deepPrefix() {
        return "../".repeat(TraversalEscapes.DEEP_LEVELS);
    }

    private static String shallowPrefix() {
        return "../".repeat(TraversalEscapes.SHALLOW_LEVELS);
    }

    private static List<TraversalPayload> payloadsOfTier(PathTraversalTier tier) {
        return ResourceTraversalPayloads.fixed().stream()
                .filter(payload -> payload.tier() == tier)
                .toList();
    }

    private static List<String> uris(List<TraversalPayload> payloads) {
        return payloads.stream().map(TraversalPayload::uri).toList();
    }
}
