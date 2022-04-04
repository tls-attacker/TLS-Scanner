/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.padding.vector;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class VeryShortPaddingGeneratorTest {

    private VeryShortPaddingGenerator generator;

    @Before
    public void setUp() {
        generator = new VeryShortPaddingGenerator();
    }

    @Test
    public void testGetVectors() {
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isCBC()) {
                List<PaddingVector> vectors = generator.getVectors(suite, ProtocolVersion.TLS12);
                for (PaddingVector vector : vectors) {
                    int length = vector.getRecordLength(suite, ProtocolVersion.TLS12, 4);
                    assertEquals("We only create vectors of the same length to omit false positives",
                        VeryShortPaddingGenerator.DEFAULT_CIPHERTEXT_LENGTH, length);
                }
            }
        }
    }
}
