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

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import org.junit.Test;

public class ExtensionRequirementTest extends RequirementsBasicTest {

    @Test
    public void testExtensionRequirement() {
        TestReport report = new TestReport();
        ExtensionType[] ext = new ExtensionType[] { ExtensionType.ALPN };

        ExtensionRequirement req = new ExtensionRequirement();
        assertTrue(req.evaluate(report));

        req = new ExtensionRequirement(new ExtensionType[0]);
        assertTrue(req.evaluate(report));

        req = new ExtensionRequirement(ext);
        assertArrayEquals(req.getRequirement(), ext);
        assertFalse(req.evaluate(report));

        Requirement reqMis = req.getMissingRequirements(report);
        assertFalse(req.evaluate(report));
        assertArrayEquals(((ExtensionRequirement) reqMis).getRequirement(), req.getRequirement());

        report.putResult(TlsAnalyzedProperty.SUPPORTED_EXTENSIONS,
            new ListResult<>(Arrays.asList(ext), "SUPPORTED_EXTENSIONS"));
        assertTrue(req.evaluate(report));
    }
}
