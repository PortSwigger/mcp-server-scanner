package com.mcpscanner.checks.catalog.commandinjection;

import java.util.Set;
import java.util.TreeSet;
import java.util.regex.MatchResult;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

enum OptionDisclosure {

    OPTION_NAMES("option names", Pattern.compile("(?<![\\w-])(?:--[A-Za-z][\\w-]+|-[A-Za-z](?![\\w-]))"), 3),
    VERSION_NUMBER("a version number", Pattern.compile("(?<![\\d.])\\d+\\.\\d+\\.\\d+(?!\\.?\\d)"), 1);

    private final String described;
    private final Pattern token;
    private final int minimum;

    OptionDisclosure(String described, Pattern token, int minimum) {
        this.described = described;
        this.token = token;
        this.minimum = minimum;
    }

    String described() {
        return described;
    }

    Set<String> in(String text, ProgramOption sent) {
        return token.matcher(text).results().map(MatchResult::group)
                .filter(found -> !found.equals(sent.flag()))
                .collect(Collectors.toCollection(TreeSet::new));
    }

    boolean enough(Set<String> disclosed) {
        return disclosed.size() >= minimum;
    }
}
