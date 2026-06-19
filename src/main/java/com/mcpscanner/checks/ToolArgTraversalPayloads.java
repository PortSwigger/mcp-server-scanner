package com.mcpscanner.checks;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public final class ToolArgTraversalPayloads {

    public record ToolArgPayload(String label, String value, PathTraversalTier tier,
                                 String differentialKey, Set<FileSignature> expectedSignatures) {}

    private static final String PASSWD_TARGET = "etc/passwd";
    private static final String WIN_INI_TARGET = "windows/win.ini";
    // The literal-slash escape prefixes (a small principled {deep, shallow} set, shared with
    // ResourceTraversalPayloads) live in TraversalEscapes — the deep prefix reaches a normalise-then-
    // check handler via the clamp principle, the shallow companion reaches a raw-prefilter handler.

    // Unlike resource/template URIs, a tool argument is a plain JSON string: a literal ../ DOES
    // reach the handler, so the plain-vs-encoded differential is fully observable here. Each plain
    // TRAVERSAL payload is paired with encoded twins sharing its differentialKey; the classifier
    // promotes the group to ENCODING_BYPASS only when the literal ../ was delivered and rejected.
    private static final List<ToolArgPayload> ABSOLUTE_PAYLOADS = List.of(
            absolute("absolute-passwd", "/etc/passwd", FileSignature.PASSWD),
            absolute("absolute-win-ini", "C:\\Windows\\win.ini", FileSignature.WIN_INI),
            absolute("file-uri-passwd", "file:///etc/passwd", FileSignature.PASSWD)
    );

    private ToolArgTraversalPayloads() {}

    public static List<ToolArgPayload> all() {
        List<ToolArgPayload> payloads = new ArrayList<>(ABSOLUTE_PAYLOADS);
        payloads.addAll(differentialFamily(PASSWD_TARGET, FileSignature.PASSWD));
        payloads.addAll(differentialFamily(WIN_INI_TARGET, FileSignature.WIN_INI));
        return List.copyOf(payloads);
    }

    private static ToolArgPayload absolute(String label, String value, FileSignature signature) {
        return new ToolArgPayload(label, value, PathTraversalTier.ABSOLUTE,
                "absolute:" + value, Set.of(signature));
    }

    private static List<ToolArgPayload> differentialFamily(String target, FileSignature signature) {
        String key = "traversal:" + target;
        List<ToolArgPayload> family = new ArrayList<>();
        for (String literalPrefix : TraversalEscapes.LITERAL_PREFIXES) {
            family.add(new ToolArgPayload("plain-traversal " + literalPrefix.length() + " " + key,
                    literalPrefix + target, PathTraversalTier.TRAVERSAL, key, Set.of(signature)));
        }
        for (TraversalEscapes.EncodedTwin twin : TraversalEscapes.ENCODED_TWINS) {
            family.add(new ToolArgPayload(twin.label() + " " + key,
                    twin.escape() + TraversalEscapes.encodeTarget(target, twin.targetEncoding()),
                    PathTraversalTier.ENCODING_BYPASS, key, Set.of(signature)));
        }
        return family;
    }
}
