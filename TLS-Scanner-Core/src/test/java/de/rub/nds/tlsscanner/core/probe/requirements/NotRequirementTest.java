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

public class NotRequirementTest {

    @Test
    public void testNotRequirement() {
        TestReport report = new TestReport();
        ProbeRequirement requirementNot = new ProbeRequirement(TlsProbeType.BASIC);

        NotRequirement requirement = new NotRequirement(null);
        assertTrue(requirement.evaluate(report));

        requirement = new NotRequirement(requirementNot);
        assertArrayEquals(requirement.getRequirement(), new Enum<?>[] {TlsProbeType.BASIC});
        assertEquals(requirement.toString(), "(not BASIC)");
        assertTrue(requirement.evaluate(report));
        report.markProbeAsExecuted(TlsProbeType.BASIC);
        assertFalse(requirement.evaluate(report));

        Requirement reqMis = requirement.getMissingRequirements(report);
        assertFalse(requirement.evaluate(report));
        assertArrayEquals(((NotRequirement) reqMis).getRequirement(), requirement.getRequirement());
    }
}
