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

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import org.junit.Test;

public class PropertyRequirementTest extends RequirementsBasicTest {

    @Test
    public void testPropertyRequirement() {
        TestReport report = new TestReport();
        TlsAnalyzedProperty[] prop = new TlsAnalyzedProperty[] { TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES };

        PropertyRequirement req = new PropertyRequirement();
        assertTrue(req.evaluate(report));

        req = new PropertyRequirement(new TlsAnalyzedProperty[0]);
        assertTrue(req.evaluate(report));

        req = new PropertyRequirement(prop);
        assertArrayEquals(req.getRequirement(), prop);
        assertFalse(req.evaluate(report));

        Requirement reqMis = req.getMissingRequirements(report);
        assertFalse(req.evaluate(report));
        assertArrayEquals(((PropertyRequirement) reqMis).getRequirement(), req.getRequirement());

        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.FALSE);
        assertFalse(req.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.TRUE);
        assertTrue(req.evaluate(report));
    }
}
