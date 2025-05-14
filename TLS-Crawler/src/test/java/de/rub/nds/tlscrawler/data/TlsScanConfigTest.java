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

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
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
}
