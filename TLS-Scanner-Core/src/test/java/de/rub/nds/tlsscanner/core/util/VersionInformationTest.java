/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.util;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class VersionInformationTest {

    @Test
    public void testVersionInformation() {
        String tlsScannerVersion = VersionInformation.getTlsScannerVersion();
        String tlsAttackerVersion = VersionInformation.getTlsAttackerVersion();
        String javaVersion = VersionInformation.getJavaVersion();
        String fullVersionInfo = VersionInformation.getFullVersionInfo();

        assertNotNull(tlsScannerVersion);
        assertNotNull(tlsAttackerVersion);
        assertNotNull(javaVersion);
        assertNotNull(fullVersionInfo);

        assertFalse(tlsScannerVersion.isEmpty());
        assertFalse(tlsAttackerVersion.isEmpty());
        assertFalse(javaVersion.isEmpty());
        assertFalse(fullVersionInfo.isEmpty());

        assertNotEquals("unknown", tlsScannerVersion);
        assertNotEquals("unknown", tlsAttackerVersion);
    }
}
