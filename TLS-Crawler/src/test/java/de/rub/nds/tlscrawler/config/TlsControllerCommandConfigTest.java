/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.crawler.config.ControllerCommandConfig;
import de.rub.nds.crawler.data.ScanConfig;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import org.junit.jupiter.api.Test;

public class TlsControllerCommandConfigTest {

    @Test
    public void testDefaultConstructor() {
        TlsControllerCommandConfig config = new TlsControllerCommandConfig();

        assertNotNull(config.getStarttlsDelegate());
        assertEquals(StarttlsType.NONE, config.getStarttlsDelegate().getStarttlsType());
    }

    @Test
    public void testGetScanConfig() {
        TlsControllerCommandConfig config = new TlsControllerCommandConfig();

        // Set configuration values via reflection since setters are not public
        try {
            java.lang.reflect.Field scanDetailField =
                    ControllerCommandConfig.class.getDeclaredField("scanDetail");
            scanDetailField.setAccessible(true);
            scanDetailField.set(config, ScannerDetail.NORMAL);

            java.lang.reflect.Field reexecutionsField =
                    ControllerCommandConfig.class.getDeclaredField("reexecutions");
            reexecutionsField.setAccessible(true);
            reexecutionsField.set(config, 3);

            java.lang.reflect.Field timeoutField =
                    ControllerCommandConfig.class.getDeclaredField("scannerTimeout");
            timeoutField.setAccessible(true);
            timeoutField.set(config, 5000);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set test properties via reflection", e);
        }

        StarttlsDelegate delegate = config.getStarttlsDelegate();
        delegate.setStarttlsType(StarttlsType.SMTP);

        ScanConfig scanConfig = config.getScanConfig();

        assertNotNull(scanConfig);
        assertEquals(TlsScanConfig.class, scanConfig.getClass());

        TlsScanConfig tlsScanConfig = (TlsScanConfig) scanConfig;
        assertEquals(ScannerDetail.NORMAL, tlsScanConfig.getScannerDetail());
        assertEquals(3, tlsScanConfig.getReexecutions());
        assertEquals(5000, tlsScanConfig.getTimeout());
        assertEquals(StarttlsType.SMTP, tlsScanConfig.getStarttlsType());
    }

    @Test
    public void testGetScannerClassForVersion() {
        TlsControllerCommandConfig config = new TlsControllerCommandConfig();
        assertEquals(TlsServerScanner.class, config.getScannerClassForVersion());
    }
}
