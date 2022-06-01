/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import org.junit.Test;

public class ProbeRequirementTest extends RequirementsBasicTest {
    @Test
    public void testProbeRequirement() {
        TestReport report = new TestReport();
        TlsProbeType probe = TlsProbeType.ALPN;

        ProbeRequirement req = new ProbeRequirement();
        assertTrue(req.evaluate(report));

        req = new ProbeRequirement(new TlsProbeType[0]);
        assertTrue(req.evaluate(report));

        req = new ProbeRequirement(probe);
        assertArrayEquals(req.getRequirement(), new TlsProbeType[] { probe });
        assertFalse(req.evaluate(report));
        report.markProbeAsExecuted(probe);
        assertTrue(req.evaluate(report));
    }

}