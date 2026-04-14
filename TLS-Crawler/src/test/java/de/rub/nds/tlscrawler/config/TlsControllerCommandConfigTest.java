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

import com.beust.jcommander.JCommander;
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
    public void testGetScannerClassForVersion() {
        TlsControllerCommandConfig config = new TlsControllerCommandConfig();
        assertEquals(TlsServerScanner.class, config.getScannerClassForVersion());
    }

    @Test
    public void testGetScanConfigUsesDefaultParallelProbes() {
        TlsControllerCommandConfig config = new TlsControllerCommandConfig();

        TlsScanConfig scanConfig = (TlsScanConfig) config.getScanConfig();

        assertEquals(1, scanConfig.getParallelProbes());
    }

    @Test
    public void testGetScanConfigUsesParsedParallelProbes() {
        TlsControllerCommandConfig config = new TlsControllerCommandConfig();
        JCommander.newBuilder()
                .addObject(config)
                .build()
                .parse("-hostFile", "resources/hostfile.txt", "-parallelProbes", "3");

        TlsScanConfig scanConfig = (TlsScanConfig) config.getScanConfig();

        assertEquals(3, scanConfig.getParallelProbes());
    }
}
