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
 * Tests for the parsing logic of StartupOptions.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class StartupOptionsTest {

    @Test
    public void CLIParsingSmokeTest() {
        String[] options = {
                "-m",
                "-i", "myinstance",
                "-o", "mymongo",
                "-r", "myredis"
        };

        StartupOptions parsed = null;
        try {
            parsed = StartupOptions.parseOptions(options);
        } catch (OptionsParsingException ex) {
            fail("Must not throw.");
        }

        assertNotNull(parsed);

        assertEquals(true, parsed.isMaster);
        assertEquals("myinstance", parsed.instanceId);
        assertEquals("mymongo", parsed.mongoDbHost);
        assertEquals("myredis", parsed.redisHost);
    }

    @Test
    public void CLIParsingInvalidArgs() {
        String[] options = {
                "-d"
        };

        try {
            StartupOptions.parseOptions(options);
            fail("Should have thrown.");
        } catch (OptionsParsingException ex) {
            // Should throw
        }
    }

    @Test
    public void CLIParsingAutoId() {
        String[] options = { };

        StartupOptions parsed = null;
        try {
            parsed = StartupOptions.parseOptions(options);
        } catch (OptionsParsingException ex) {
            fail("Must not throw.");
        }

        assertNotNull(parsed);
        assertNotNull(parsed.instanceId);
        assertNotEquals("", parsed.instanceId);
    }

    @Test
    public void getHelpStringSmokeTest() {
        String help = StartupOptions.getHelpString();

        assertNotNull(help);
        assertNotEquals("", help);
    }

    @Test
    public void autoWorkspaceTest() {
        String[] options = { };

        StartupOptions parsed = null;
        try {
            parsed = StartupOptions.parseOptions(options);
        } catch (OptionsParsingException ex) {
            fail("Must not throw.");
        }

        assertNotNull(parsed);
        assertNotNull(parsed.workspace);
        assertNotEquals("", parsed.workspace);
    }
}