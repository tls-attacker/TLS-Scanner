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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import org.junit.Test;

public class OrRequirementTest extends RequirementsBasicTest {

    @Test
    public void testOrRequirement() {
        TestReport report = new TestReport();

        ProbeRequirement req0 = new ProbeRequirement(TlsProbeType.ALPN);
        ProbeRequirement req1 = new ProbeRequirement(TlsProbeType.BASIC);

        OrRequirement req = new OrRequirement();
        assertTrue(req.evaluate(report));

        req = new OrRequirement(new Requirement[0]);
        assertTrue(req.evaluate(report));

        req = new OrRequirement(req0, req1);
        assertArrayEquals(req.getRequirement(), new Requirement[] { req0, req1 });
        assertFalse(req.evaluate(report));

        Requirement reqMis = req.getMissingRequirements(report);
        assertFalse(req.evaluate(report));
        assertArrayEquals(((OrRequirement) reqMis).getRequirement(), req.getRequirement());

        report.markProbeAsExecuted(TlsProbeType.BASIC);
        assertTrue(req.evaluate(report));

        reqMis = req.getMissingRequirements(report);
        assertEquals(reqMis, Requirement.NO_REQUIREMENT);
    }
}
