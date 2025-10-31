/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.data;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.ProbeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class TlsScanConfigTest {

    @Test
    public void testTlsScanConfigInitialization() {
        ScannerDetail scannerDetail = ScannerDetail.NORMAL;
        int reexecutions = 2;
        int timeout = 1000;
        StarttlsType starttlsType = StarttlsType.NONE;

        TlsScanConfig config =
                new TlsScanConfig(scannerDetail, reexecutions, timeout, starttlsType);

        assertEquals(scannerDetail, config.getScannerDetail());
        assertEquals(reexecutions, config.getReexecutions());
        assertEquals(timeout, config.getTimeout());
        assertEquals(starttlsType, config.getStarttlsType());
    }

    @Test
    public void testStarttlsTypeSetter() {
        TlsScanConfig config = new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, StarttlsType.NONE);

        assertEquals(StarttlsType.NONE, config.getStarttlsType());

        config.setStarttlsType(StarttlsType.SMTP);
        assertEquals(StarttlsType.SMTP, config.getStarttlsType());
    }

    @Test
    public void testTlsScanConfigWithExcludedProbes() {
        ScannerDetail scannerDetail = ScannerDetail.DETAILED;
        int reexecutions = 3;
        int timeout = 2000;
        StarttlsType starttlsType = StarttlsType.IMAP;
        List<ProbeType> excludedProbes =
                Arrays.asList(TlsProbeType.CIPHER_SUITE, TlsProbeType.HEARTBLEED);

        TlsScanConfig config =
                new TlsScanConfig(
                        scannerDetail, reexecutions, timeout, starttlsType, excludedProbes);

        assertEquals(scannerDetail, config.getScannerDetail());
        assertEquals(reexecutions, config.getReexecutions());
        assertEquals(timeout, config.getTimeout());
        assertEquals(starttlsType, config.getStarttlsType());
        assertNotNull(config.getExcludedProbes());
        assertEquals(2, config.getExcludedProbes().size());
        assertEquals("Cipher suite", config.getExcludedProbes().get(0).getName());
        assertEquals("Heartbleed", config.getExcludedProbes().get(1).getName());
    }

    @Test
    public void testTlsScanConfigWithoutExcludedProbes() {
        TlsScanConfig config = new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, StarttlsType.NONE);

        assertNull(config.getExcludedProbes());
    }

    @Test
    public void testExcludedProbesSetterOnTlsScanConfig() {
        TlsScanConfig config = new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, StarttlsType.NONE);
        assertNull(config.getExcludedProbes());

        List<ProbeType> excludedProbes =
                Arrays.asList(
                        TlsProbeType.BLEICHENBACHER, TlsProbeType.DROWN, TlsProbeType.EARLY_CCS);
        config.setExcludedProbes(excludedProbes);

        assertNotNull(config.getExcludedProbes());
        assertEquals(3, config.getExcludedProbes().size());
        assertEquals("Bleichenbacher", config.getExcludedProbes().get(0).getName());
        assertEquals("Drown", config.getExcludedProbes().get(1).getName());
        assertEquals("Early CCS", config.getExcludedProbes().get(2).getName());
    }
}
