package com.mcpscanner.scan;

import java.util.List;
import java.util.Locale;

public final class PathArgumentHeuristic {

    private static final List<String> NAME_HINTS = List.of(
            "path", "file", "filename", "filepath", "file_path",
            "dir", "directory", "folder", "target", "source",
            "location", "resource", "document", "attachment", "archive",
            "download_path", "upload_path", "workspace_path"
    );

    private static final List<String> DESCRIPTION_HINTS = List.of(
            "file", "path", "directory", "folder", "read", "load", "open", "download"
    );

    private PathArgumentHeuristic() {}

    public static boolean isPathLike(String argName, String description) {
        return matchesHint(argName, NAME_HINTS) || matchesHint(description, DESCRIPTION_HINTS);
    }

    private static boolean matchesHint(String value, List<String> hints) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        for (String hint : hints) {
            if (lower.contains(hint)) {
                return true;
            }
        }
        return false;
    }
}
