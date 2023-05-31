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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class ProtocolRequirementTest {
    @Test
    public void testProtocolRequirement() {
        TestReport report = new TestReport();
        ProtocolVersion[] protocolVersion = new ProtocolVersion[] {ProtocolVersion.TLS10};

        ProtocolRequirement requirement = new ProtocolRequirement();
        assertTrue(requirement.evaluate(report));

        requirement = new ProtocolRequirement(new ProtocolVersion[0]);
        assertTrue(requirement.evaluate(report));

        requirement = new ProtocolRequirement(protocolVersion);
        assertArrayEquals(requirement.getRequirement(), protocolVersion);
        assertFalse(requirement.evaluate(report));

        Requirement requirementMissing = requirement.getMissingRequirements(report);
        assertFalse(requirement.evaluate(report));
        assertArrayEquals(
                ((ProtocolRequirement) requirementMissing).getRequirement(),
                requirement.getRequirement());

        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                new ListResult<>(
                        Arrays.asList(protocolVersion),
                        TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS.name()));
        assertTrue(requirement.evaluate(report));
    }
}
