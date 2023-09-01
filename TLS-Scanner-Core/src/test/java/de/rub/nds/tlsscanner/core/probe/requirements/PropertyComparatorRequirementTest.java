/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class PropertyComparatorRequirementTest {

    @Test
    public void testPropertyComparatorRequirement() {
        TlsAnalyzedProperty property = TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS;
        TestReport report0 = new TestReport(),
                report1 = new TestReport(),
                report2 = new TestReport();
        ListResult<ProtocolVersion> protVer1 =
                new ListResult<>(
                        Arrays.asList(ProtocolVersion.TLS10),
                        TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS.name());
        ListResult<ProtocolVersion> protVer2 =
                new ListResult<>(
                        Arrays.asList(ProtocolVersion.TLS10, ProtocolVersion.DTLS12),
                        "SUPPORTED_PROTOCOL_VERSIONS");
        report1.putResult(property, protVer1);
        report2.putResult(property, protVer2);

        // normal values
        Requirement requirementGreater =
                new PropertyComparatorRequirement(
                        PropertyComparatorRequirement.GREATER, property, 2);
        Requirement requirementSmaller =
                new PropertyComparatorRequirement(
                        PropertyComparatorRequirement.SMALLER, property, 2);
        Requirement requirementEqual =
                new PropertyComparatorRequirement(PropertyComparatorRequirement.EQUAL, property, 2);

        // illegal
        Requirement requirementNegative =
                new PropertyComparatorRequirement(
                        PropertyComparatorRequirement.EQUAL, property, -2);
        Requirement requirementNullProperty =
                new PropertyComparatorRequirement(PropertyComparatorRequirement.EQUAL, null, 2);
        Requirement requirementNullValue =
                new PropertyComparatorRequirement(
                        PropertyComparatorRequirement.EQUAL, property, null);

        // true cases
        assertTrue(requirementEqual.evaluate(report2)); // 2 == 2
        assertTrue(requirementSmaller.evaluate(report1)); // 1 < 2

        // false cases
        assertFalse(requirementEqual.evaluate(report0)); // property not set in report
        assertFalse(requirementGreater.evaluate(report0)); // property not set in report
        assertFalse(requirementSmaller.evaluate(report0)); // property not set in report

        assertFalse(requirementSmaller.evaluate(report2)); // not 2<2
        assertFalse(requirementEqual.evaluate(report1)); // not 2=1
        assertFalse(requirementGreater.evaluate(report1)); // not 1>2
        assertFalse(requirementGreater.evaluate(report2)); // not 2>2

        // illegal and false
        assertFalse(requirementNegative.evaluate(report2));
        assertFalse(requirementNullProperty.evaluate(report2));
        assertFalse(requirementNullValue.evaluate(report2));
    }
}
