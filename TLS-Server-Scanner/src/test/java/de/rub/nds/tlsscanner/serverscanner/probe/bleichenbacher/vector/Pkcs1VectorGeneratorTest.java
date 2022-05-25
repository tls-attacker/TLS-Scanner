/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherScanType;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;

public class Pkcs1VectorGeneratorTest {

    /**
     * Test of generatePlainPkcs1Vectors method, of class Pkcs1VectorGenerator.
     */
    @Test
    public void testGeneratePlainPkcs1Vectors() {
        List<Pkcs1Vector> vectors =
            Pkcs1VectorGenerator.generatePlainPkcs1Vectors(2048, BleichenbacherScanType.FAST, ProtocolVersion.TLS12);
        Assert.assertNotNull(vectors);
        Assert.assertEquals("11 PKCS#1 vectors should be generated", 12, vectors.size());
    }

}
