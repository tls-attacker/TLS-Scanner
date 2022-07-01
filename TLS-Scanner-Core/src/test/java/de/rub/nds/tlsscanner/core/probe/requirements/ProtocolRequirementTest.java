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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import org.junit.Test;

public class ProtocolRequirementTest {
    @Test
    public void testProtocolRequirement() {
        TestReport report = new TestReport();
        ProtocolVersion[] protocolVersion = new ProtocolVersion[] { ProtocolVersion.TLS10 };

        ProtocolRequirement requirement = new ProtocolRequirement();
        assertTrue(requirement.evaluate(report));

        requirement = new ProtocolRequirement(new ProtocolVersion[0]);
        assertTrue(requirement.evaluate(report));

        requirement = new ProtocolRequirement(protocolVersion);
        assertArrayEquals(requirement.getRequirement(), protocolVersion);
        assertFalse(requirement.evaluate(report));

        Requirement requirementMissing = requirement.getMissingRequirements(report);
        assertFalse(requirement.evaluate(report));
        assertArrayEquals(((ProtocolRequirement) requirementMissing).getRequirement(), requirement.getRequirement());

        report.putResult(TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
            new ListResult<>(Arrays.asList(protocolVersion), "SUPPORTED_PROTOCOL_VERSIONS"));
        assertTrue(requirement.evaluate(report));
    }
}
