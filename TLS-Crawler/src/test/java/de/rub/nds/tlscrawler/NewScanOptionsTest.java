/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests for the NewScanOptions class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class NewScanOptionsTest {

    private String[] optionsA = {
            "-h",
            "-s", "a,b,c",
            "-p", "1234,2345,3456",
            "-r", "myredis"
    };

    private String[] optionsB = {
            "-s", "d,e,f",
            "-p", "7,8,9",
            "-n"
    };

    private String[] optionsHelpOnly = {
            "-h"
    };

    private String[] optionsNone = { };

    @Test
    public void getHelpStringTest() {
        String subject = NewScanOptions.getHelpString();

        assertNotNull(subject);
        assertNotEquals(0, subject.length());
    }

    @Test
    public void parseOptionsSmokeTest() {
        NewScanOptions opts = NewScanOptions.parseOptions(optionsA);

        assertTrue(opts.help);

        assertEquals(3, opts.scans.size());
        assertTrue(opts.scans.contains("a"));
        assertTrue(opts.scans.contains("b"));
        assertTrue(opts.scans.contains("c"));

        assertEquals(3, opts.ports.size());
        assertTrue(opts.ports.contains("1234"));
        assertTrue(opts.ports.contains("2345"));
        assertTrue(opts.ports.contains("3456"));

        assertEquals("myredis", opts.targetsFromRedisList);

        opts = NewScanOptions.parseOptions(optionsB);

        assertFalse(opts.help);

        assertEquals(3, opts.scans.size());
        assertTrue(opts.scans.contains("d"));
        assertTrue(opts.scans.contains("e"));
        assertTrue(opts.scans.contains("f"));

        assertEquals(3, opts.ports.size());
        assertTrue(opts.ports.contains("7"));
        assertTrue(opts.ports.contains("8"));
        assertTrue(opts.ports.contains("9"));

        assertEquals("", opts.targetsFromRedisList);

        assertTrue(opts.ndsBlacklist);
    }

    @Test
    public void helpOnlyTest() {
        NewScanOptions opts = NewScanOptions.parseOptions(optionsHelpOnly);

        assertTrue(opts.help);

        assertEquals(0, opts.scans.size());

        assertEquals(0, opts.ports.size());

        assertEquals("", opts.targetsFromRedisList);

        assertEquals(0, opts.whitelist.size());

        assertEquals(0, opts.blacklist.size());

        assertTrue(opts.ndsBlacklist);
    }

    @Test
    public void noArgsTest() {
        NewScanOptions opts = NewScanOptions.parseOptions(optionsNone);

        assertTrue(opts.help);

        assertEquals(0, opts.scans.size());

        assertEquals(0, opts.ports.size());

        assertEquals("", opts.targetsFromRedisList);

        assertEquals(0, opts.whitelist.size());

        assertEquals(0, opts.blacklist.size());

        assertTrue(opts.ndsBlacklist);
    }
}