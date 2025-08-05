/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.TlsCoreTestReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ExtensionRequirementTest {

    @Test
    public void testExtensionRequirement() {
        TlsCoreTestReport report = new TlsCoreTestReport();
        ExtensionType[] extension = new ExtensionType[] {ExtensionType.ALPN};

        ExtensionRequirement<TlsCoreTestReport> requirement = new ExtensionRequirement<>();
        assertTrue(requirement.evaluate(report));

        requirement = new ExtensionRequirement<>();
        assertTrue(requirement.evaluate(report));

        requirement = new ExtensionRequirement<>(extension);
        assertArrayEquals(requirement.getParameters().toArray(), extension);
        assertFalse(requirement.evaluate(report));

        List<Requirement<TlsCoreTestReport>> unfulfilled =
                requirement.getUnfulfilledRequirements(report);
        assertFalse(requirement.evaluate(report));
        assertEquals(1, unfulfilled.size());
        assertEquals(requirement, unfulfilled.get(0));

        report.putResult(TlsAnalyzedProperty.SUPPORTED_EXTENSIONS, List.of(extension));
        assertTrue(requirement.evaluate(report));
    }
}
