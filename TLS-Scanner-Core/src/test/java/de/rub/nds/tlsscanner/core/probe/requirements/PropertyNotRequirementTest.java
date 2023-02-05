/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import org.junit.jupiter.api.Test;

public class PropertyNotRequirementTest {

    @Test
    public void testPropertyNotRequirement() {
        TestReport report = new TestReport();
        TlsAnalyzedProperty[] propertyNot =
                new TlsAnalyzedProperty[] {TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES};

        PropertyNotRequirement requirement = new PropertyNotRequirement();
        assertTrue(requirement.evaluate(report));

        requirement = new PropertyNotRequirement(new TlsAnalyzedProperty[0]);
        assertTrue(requirement.evaluate(report));

        requirement = new PropertyNotRequirement(propertyNot);
        assertArrayEquals(requirement.getRequirement(), propertyNot);
        assertFalse(requirement.evaluate(report));

        Requirement reqMis = requirement.getMissingRequirements(report);
        assertFalse(requirement.evaluate(report));
        assertArrayEquals(
                ((PropertyNotRequirement) reqMis).getRequirement(), requirement.getRequirement());

        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.TRUE);
        assertFalse(requirement.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.FALSE);
        assertTrue(requirement.evaluate(report));
    }
}
