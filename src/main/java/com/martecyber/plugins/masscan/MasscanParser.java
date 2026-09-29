package com.martecyber.plugins.masscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Parses masscan JSON output (masscan -oJ).
 *
 * [
 *   {"ip":"1.2.3.4","timestamp":"1234567890",
 *    "ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64}]}
 * ]
 *
 * Asset chain per open port: IP → INTERFACE → SERVICE
 */
public class MasscanParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId()      { return "masscan"; }
    @Override public String getDisplayName() { return "Masscan JSON"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".json"}; }

    @Override
    public boolean validate(byte[] content) {
        String text = new String(content, StandardCharsets.UTF_8).stripLeading();
        // Masscan JSON starts with '[' and entries have "ports" array
        if (text.startsWith("[")) return text.contains("\"ports\"") && text.contains("\"ip\"");
        // Fallback: JSONL-like with leading comma per line
        String first = ScannerParserUtils.firstNonEmptyLine(content);
        String clean = first.startsWith(",") ? first.substring(1).trim() : first;
        return clean.startsWith("{") && clean.contains("\"ports\"") && clean.contains("\"ip\"");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        Set<String> seen   = new HashSet<>();

        List<JsonNode> entries = readEntries(content, result);
        for (JsonNode entry : entries) {
            try {
                processEntry(entry, result, seen);
            } catch (Exception e) {
                result.addWarning("Skipping entry: " + e.getMessage());
            }
        }
        return result;
    }

    private List<JsonNode> readEntries(byte[] content, ParseResult result) {
        List<JsonNode> entries = new ArrayList<>();
        String text = new String(content, StandardCharsets.UTF_8).strip();

        // Try as a JSON array first
        if (text.startsWith("[")) {
            try {
                JsonNode arr = MAPPER.readTree(text);
                arr.forEach(entries::add);
                return entries;
            } catch (Exception ignored) {}
        }

        // Fallback: line-by-line (masscan prepends ',' to all but first object)
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(content), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.startsWith(",")) line = line.substring(1).trim();
                if (!line.isEmpty() && line.startsWith("{")) {
                    try { entries.add(MAPPER.readTree(line)); }
                    catch (Exception e) { result.addWarning("Skipping line: " + e.getMessage()); }
                }
            }
        } catch (Exception ignored) {}
        return entries;
    }

    private void processEntry(JsonNode node, ParseResult result, Set<String> seen) {
        String ip = node.path("ip").asText(null);
        if (ip == null || ip.isBlank() || !ScannerParserUtils.isIp(ip)) return;

        ScannerParserUtils.emitHostChain(ip, result, seen);

        JsonNode ports = node.get("ports");
        if (ports == null || !ports.isArray()) return;

        ports.forEach(p -> {
            int    port   = p.path("port").asInt(0);
            String proto  = p.path("proto").asText("tcp");
            String status = p.path("status").asText("open");
            String reason = p.path("reason").asText(null);
            if (port > 0 && "open".equalsIgnoreCase(status)) {
                ScannerParserUtils.emitService(ip, port, proto, reason, result, seen);
            }
        });
    }
}
