package com.martecyber.plugins.masscan;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link MasscanParser}'s two accepted shapes — a real JSON array, and masscan's
 *  "line-by-line, leading comma" streaming shape used when a scan is interrupted before the
 *  closing {@code ]} is written — plus its open/closed-port filtering. */
class MasscanParserTest {

    private final MasscanParser parser = new MasscanParser();

    @Test
    void validateAcceptsAJsonArrayWithPortsAndIp() {
        assertTrue(parser.validate("[{\"ip\":\"1.2.3.4\",\"ports\":[{\"port\":80}]}]".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("{\"ip\":\"1.2.3.4\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void validateAcceptsTheLeadingCommaStreamingShape() {
        assertTrue(parser.validate(",{\"ip\":\"1.2.3.4\",\"ports\":[{\"port\":80}]}\n".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void parsesAWellFormedJsonArrayAndEmitsOnlyOpenPorts() throws Exception {
        String json = """
            [
              {"ip":"1.2.3.4","ports":[
                {"port":80,"proto":"tcp","status":"open","reason":"syn-ack"},
                {"port":81,"proto":"tcp","status":"closed","reason":"reset"}
              ]}
            ]
            """;
        ParseResult result = parser.parse(json.getBytes(StandardCharsets.UTF_8));

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.SERVICE) && a.getIdentifier().equals("1.2.3.4:80/tcp")));
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getIdentifier().equals("1.2.3.4:81/tcp")));
    }

    @Test
    void parsesTheLeadingCommaLineByLineFallbackWhenNotAValidArray() throws Exception {
        // Masscan writes one entry per line prefixed with ',' (all but the first) while a scan
        // is still running — the file may never get its closing ']', so the parser must fall
        // back to line-by-line reading when the whole-content array parse fails.
        String streaming = "[\n"
            + "{\"ip\":\"1.2.3.4\",\"ports\":[{\"port\":22,\"proto\":\"tcp\",\"status\":\"open\"}]}\n"
            + ",{\"ip\":\"5.6.7.8\",\"ports\":[{\"port\":443,\"proto\":\"tcp\",\"status\":\"open\"}]}\n";
        ParseResult result = parser.parse(streaming.getBytes(StandardCharsets.UTF_8));

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("1.2.3.4:22/tcp")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("5.6.7.8:443/tcp")));
    }

    @Test
    void entryWithAnInvalidIpIsSkipped() throws Exception {
        ParseResult result = parser.parse("[{\"ip\":\"not-an-ip\",\"ports\":[{\"port\":80,\"status\":\"open\"}]}]".getBytes(StandardCharsets.UTF_8));
        assertTrue(result.getAssets().isEmpty());
    }

    @Test
    void hostChainIsStillEmittedEvenWithoutAPortsArray() throws Exception {
        ParseResult result = parser.parse("[{\"ip\":\"1.2.3.4\"}]".getBytes(StandardCharsets.UTF_8));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.IP) && a.getIdentifier().equals("1.2.3.4")));
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getType().equals(AssetType.SERVICE)));
    }
}
