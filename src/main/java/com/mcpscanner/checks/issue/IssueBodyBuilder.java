package com.mcpscanner.checks.issue;

import java.util.List;

public final class IssueBodyBuilder {

    private final StringBuilder body = new StringBuilder();

    public IssueBodyBuilder paragraph(String text) {
        body.append("<p>").append(escape(text)).append("</p>");
        return this;
    }

    public IssueBodyBuilder findings(List<String> items) {
        if (items == null || items.isEmpty()) {
            return this;
        }
        body.append("<ul>");
        for (String item : items) {
            body.append("<li>").append(escape(item)).append("</li>");
        }
        body.append("</ul>");
        return this;
    }

    public IssueBodyBuilder section(String headingHtml, String bodyHtml) {
        body.append("<p><b>").append(escape(headingHtml)).append("</b></p>").append(bodyHtml);
        return this;
    }

    public IssueBodyBuilder vulnerabilityClassifications(List<Cwe> cwes) {
        if (cwes == null || cwes.isEmpty()) {
            return this;
        }
        body.append("<p><b>Vulnerability classifications</b></p><ul>");
        for (Cwe cwe : cwes) {
            body.append("<li><a href=\"").append(escape(cwe.url())).append("\">")
                    .append(escape(cwe.label())).append("</a></li>");
        }
        body.append("</ul>");
        return this;
    }

    public IssueBodyBuilder references(List<String> urls) {
        if (urls == null || urls.isEmpty()) {
            return this;
        }
        body.append("<p><b>References</b></p><ul>");
        for (String url : urls) {
            String escaped = escape(url);
            body.append("<li><a href=\"").append(escaped).append("\">").append(escaped).append("</a></li>");
        }
        body.append("</ul>");
        return this;
    }

    public String build() {
        return body.toString();
    }

    private static String escape(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '&' -> escaped.append("&amp;");
                case '<' -> escaped.append("&lt;");
                case '>' -> escaped.append("&gt;");
                case '"' -> escaped.append("&quot;");
                case '\'' -> escaped.append("&#39;");
                default -> escaped.append(c);
            }
        }
        return escaped.toString();
    }
}
