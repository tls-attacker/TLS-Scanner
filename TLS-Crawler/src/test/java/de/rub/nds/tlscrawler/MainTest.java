/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.OptionsParsingException;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests for the Main class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class MainTest {

    @Test
    public void CLIParsingSmokeTest() {
        String[] options = {
                "-m",
                "-i", "myinstance",
                "-o", "mymongo",
                "-r", "myredis"
        };

        CLOptions parsed = null;
        try {
            parsed = Main.parseOptions(options);
        } catch (OptionsParsingException ex) {
            fail();
        }

        assertNotNull(parsed);

        assertEquals(true, parsed.isMaster);
        assertEquals("myinstance", parsed.instanceId);
        assertEquals("mymongo", parsed.mongoDbConnectionString);
        assertEquals("myredis", parsed.redisConnectionString);
    }

    @Test
    public void CLIParsingInvalidArgs() {
        String[] options = {
                "-d"
        };

        try {
            Main.parseOptions(options);
            fail();
        } catch (OptionsParsingException ex) {
            // Should throw
        }
    }
}