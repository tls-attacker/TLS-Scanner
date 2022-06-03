/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import org.junit.Test;

public class NotRequirementTest extends RequirementsBasicTest {

    @Test
    public void testNotRequirement() {
        TestReport report = new TestReport();
        ProbeRequirement reqNot = new ProbeRequirement(TlsProbeType.BASIC);

        NotRequirement req = new NotRequirement(null);
        assertTrue(req.evaluate(report));

        req = new NotRequirement(reqNot);
        assertEquals(req.getRequirement(), reqNot);
        assertTrue(req.evaluate(report));
        report.markProbeAsExecuted(TlsProbeType.BASIC);
        assertFalse(req.evaluate(report));

        Requirement reqMis = req.getMissingRequirements(report);
        assertFalse(req.evaluate(report));
        assertEquals(((NotRequirement) reqMis).getRequirement(), req.getRequirement());
    }
}
