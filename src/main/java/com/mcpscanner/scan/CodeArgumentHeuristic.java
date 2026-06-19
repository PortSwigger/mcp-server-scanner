package com.mcpscanner.scan;

import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class CodeArgumentHeuristic {

    private static final Set<String> NAME_HINTS = Set.of(
            "code", "script", "expression", "expr", "format", "template",
            "query", "cmd", "command", "eval", "exec", "program",
            // `source_code` is intentionally NOT listed: the `_` token boundary splits it into
            // [source, code], so the `code` token already matches it as a whole token.
            "js", "python", "shell",
            // Shell-injection-prone argument vocabulary. Real command-injection MCP
            // CVEs (e.g. CVE-2025-53107 git-mcp-server `initialBranch`/`branchName`,
            // CVE-2025-54073 mcp-package-docs `package`) inject through innocuous
            // string args interpolated into a shell command, not args named `code`.
            // The RCE check only probes user-selected tools and only reports on a
            // confirmed out-of-band callback, so a non-sink match here costs a few
            // harmless HTTP probes while a miss is a silent false negative.
            "branch", "package", "repository", "repo", "url",
            "path", "dir", "directory", "file", "target", "remote",
            "tag", "commit", "host", "domain"
    );

    private static final List<String> DESCRIPTION_HINTS = List.of(
            "eval", "execute", "run", "command", "expression", "code", "script"
    );

    // High-signal filesystem/command-injection sink stems for all-lowercase compounds with no
    // camelCase/underscore boundary (filepath, filename, branchname, targetpath) that whole-token
    // matching cannot split. Matched only at a compound boundary (prefix or suffix), and `file` only
    // as a PREFIX so `profile` (file as a suffix) stays out — the other stems are substrings of none
    // of the known false-friends (profile/redirect/report/stage/username/referrer/count).
    private static final List<String> COMPOUND_SINK_PREFIX_OR_SUFFIX_STEMS = List.of("path", "branch");
    private static final String FILE_PREFIX_STEM = "file";

    private static final String TOKEN_BOUNDARY = String.join("|",
            "(?<=[a-z0-9])(?=[A-Z])",   // camelCase: fooBar -> foo|Bar
            "(?<=[A-Z])(?=[A-Z][a-z])", // acronym followed by word: HTTPServer -> HTTP|Server
            "[^A-Za-z0-9]+"             // underscores, hyphens, dots, other separators
    );

    private CodeArgumentHeuristic() {}

    public static boolean isCodeLike(String argName, String description) {
        return nameTokenMatchesHint(argName)
                || nameIsCompoundSink(argName)
                || descriptionContainsHint(description);
    }

    private static boolean nameTokenMatchesHint(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        for (String token : name.split(TOKEN_BOUNDARY)) {
            if (NAME_HINTS.contains(token.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static boolean nameIsCompoundSink(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.startsWith(FILE_PREFIX_STEM)) {
            return true;
        }
        for (String stem : COMPOUND_SINK_PREFIX_OR_SUFFIX_STEMS) {
            if (lower.startsWith(stem) || lower.endsWith(stem)) {
                return true;
            }
        }
        return false;
    }

    private static boolean descriptionContainsHint(String description) {
        if (description == null || description.isEmpty()) {
            return false;
        }
        String lower = description.toLowerCase(Locale.ROOT);
        for (String hint : DESCRIPTION_HINTS) {
            if (lower.contains(hint)) {
                return true;
            }
        }
        return false;
    }
}
