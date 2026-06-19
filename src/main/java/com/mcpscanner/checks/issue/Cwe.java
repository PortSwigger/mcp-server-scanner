package com.mcpscanner.checks.issue;

public record Cwe(int id, String title) {

    public String url() {
        return "https://cwe.mitre.org/data/definitions/" + id + ".html";
    }

    public String label() {
        return "CWE-" + id + ": " + title;
    }
}
