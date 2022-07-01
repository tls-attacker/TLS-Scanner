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

public class ExtensionRequirementTest {

    @Test
    public void testExtensionRequirement() {
        TestReport report = new TestReport();
        ExtensionType[] extension = new ExtensionType[] { ExtensionType.ALPN };

        ExtensionRequirement requirement = new ExtensionRequirement();
        assertTrue(requirement.evaluate(report));

        requirement = new ExtensionRequirement(new ExtensionType[0]);
        assertTrue(requirement.evaluate(report));

        requirement = new ExtensionRequirement(extension);
        assertArrayEquals(requirement.getRequirement(), extension);
        assertFalse(requirement.evaluate(report));

        Requirement requirementMissing = requirement.getMissingRequirements(report);
        assertFalse(requirement.evaluate(report));
        assertArrayEquals(((ExtensionRequirement) requirementMissing).getRequirement(), requirement.getRequirement());

        report.putResult(TlsAnalyzedProperty.SUPPORTED_EXTENSIONS,
            new ListResult<>(Arrays.asList(extension), "SUPPORTED_EXTENSIONS"));
        assertTrue(requirement.evaluate(report));
    }
}
