package com.mcpscanner.cvetargets.manifest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

final class TargetScripts {

    private TargetScripts() {
    }

    static void requireInTargetDirectory(LoadedTarget target, String field, String script, List<String> violations) {
        Path resolved = target.directory().resolve(script).normalize();
        if (!resolved.startsWith(target.directory().normalize()) || !Files.isRegularFile(resolved)) {
            violations.add(field + ": provision script " + script + " does not exist in the target directory");
        }
    }
}
