package com.mcpscanner.checks.catalog.commandinjection;

enum ProgramOption {

    HELP("--help"),
    VERSION("--version");

    private final String flag;

    ProgramOption(String flag) {
        this.flag = flag;
    }

    String flag() {
        return flag;
    }

    String undashed() {
        return flag.replaceFirst("^-+", "");
    }
}
