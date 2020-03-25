/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import org.junit.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Class with tests for the TlsCrawlerMaster.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsCrawlerMasterTest {

    @Test
    public void isValidIp_SmokeTest() {
        assertTrue(TlsCrawlerMaster.isValidIp("192.168.34.32"));
        assertFalse(TlsCrawlerMaster.isValidIp("Hallo."));
    }

    @Test
    public void isValidIp_Valid1() {
        assertTrue(TlsCrawlerMaster.isValidIp("1.0.0.0"));
    }

    @Test
    public void isValidIp_Valid2() {
        assertTrue(TlsCrawlerMaster.isValidIp("192.168.1.1"));
    }

    @Test
    public void isValidIp_Valid3() {
        assertTrue(TlsCrawlerMaster.isValidIp("255.255.255.255"));
    }

    @Test
    public void isValidIp_Invalid1() {
        assertFalse(TlsCrawlerMaster.isValidIp("10.168.0001.100"));
    }

    @Test
    public void isValidIp_Invalid2() {
        assertFalse(TlsCrawlerMaster.isValidIp("0.0.0.256"));
    }

    @Test
    public void isValidIp_Invalid3() {
        assertFalse(TlsCrawlerMaster.isValidIp("256.255.255.255"));
    }

    @Test
    public void isValidIp_Invalid4() {
        assertFalse(TlsCrawlerMaster.isValidIp("256.0.0.0"));
    }

    @Test
    public void isValidIp_Invalid5() {
        assertFalse(TlsCrawlerMaster.isValidIp("192.168. 224.0"));
    }

    @Test
    public void isValidIp_Invalid6() {
        assertFalse(TlsCrawlerMaster.isValidIp("192.168.224.0 1"));
    }

    @Test
    public void isValidIp_PerformanceValid() {
        Instant start = Instant.now();

        for (long i = 0; i < (256 * 256 * 256); i++) {
            TlsCrawlerMaster.isValidIp("192.168.16.1");
        }

        Instant stop = Instant.now();

        long ms = Duration.between(start, stop).toMillis();
        assertTrue(ms <= 120000);
    }
}