/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

import org.junit.jupiter.api.Test;

public class OrRequirementTest {

    @Test
    public void testOrRequirement() {
        TestReport report = new TestReport();

        ProbeRequirement requirement0 = new ProbeRequirement(TlsProbeType.ALPN);
        ProbeRequirement requirement1 = new ProbeRequirement(TlsProbeType.BASIC);

        OrRequirement requirement = new OrRequirement();
        assertTrue(requirement.evaluate(report));

        requirement = new OrRequirement(new Requirement[0]);
        assertTrue(requirement.evaluate(report));

        requirement = new OrRequirement(requirement0, requirement1);
        assertArrayEquals(
                requirement.getRequirement(),
                new Enum<?>[] {TlsProbeType.ALPN, TlsProbeType.BASIC});
        assertEquals(requirement.toString(), "(ALPN or BASIC)");
        assertEquals(requirement.name(), "(ALPN or BASIC)");
        assertFalse(requirement.evaluate(report));

        Requirement requirementMissing = requirement.getMissingRequirements(report);
        assertFalse(requirement.evaluate(report));
        assertArrayEquals(
                ((OrRequirement) requirementMissing).getRequirement(),
                requirement.getRequirement());

        report.markProbeAsExecuted(TlsProbeType.BASIC);
        assertTrue(requirement.evaluate(report));

        requirementMissing = requirement.getMissingRequirements(report);
        assertEquals(requirementMissing, Requirement.NO_REQUIREMENT);
    }
}
