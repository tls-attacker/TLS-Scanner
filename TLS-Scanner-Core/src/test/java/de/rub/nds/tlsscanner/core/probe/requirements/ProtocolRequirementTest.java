/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.TlsCoreTestReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ProtocolRequirementTest {
    @Test
    public void testProtocolRequirement() {
        TlsCoreTestReport report = new TlsCoreTestReport();
        ProtocolVersion[] protocolVersion = new ProtocolVersion[] {ProtocolVersion.TLS10};

        ProtocolVersionRequirement<TlsCoreTestReport> requirement =
                new ProtocolVersionRequirement<>();
        assertTrue(requirement.evaluate(report));

        requirement = new ProtocolVersionRequirement<>(new ProtocolVersion[0]);
        assertTrue(requirement.evaluate(report));

        requirement = new ProtocolVersionRequirement<>(protocolVersion);
        assertArrayEquals(requirement.getParameters().toArray(), protocolVersion);
        assertFalse(requirement.evaluate(report));

        report.putResult(TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS, List.of(protocolVersion));
        assertTrue(requirement.evaluate(report));
    }
}
