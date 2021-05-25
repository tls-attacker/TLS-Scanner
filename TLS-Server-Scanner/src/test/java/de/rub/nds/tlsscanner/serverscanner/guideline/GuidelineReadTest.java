/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.guideline.model.Guideline;
import org.junit.Test;

import java.io.IOException;

public class GuidelineReadTest {

    @Test
    public void readGuideline() throws IOException {
        Guideline nist = GuidelineIO.readGuideline("/guideline/NIST.SP.800-52r2.xml");

        System.out.println(nist);
    }
}
