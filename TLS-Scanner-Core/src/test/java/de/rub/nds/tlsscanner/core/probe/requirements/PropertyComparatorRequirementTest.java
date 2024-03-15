/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class PropertyComparatorRequirementTest {

    @Test
    public void testPropertyComparatorRequirement() {
        TlsAnalyzedProperty property = TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS;
        TestReport report0 = new TestReport(),
                report1 = new TestReport(),
                report2 = new TestReport();
        ListResult<ProtocolVersion> protVer1 =
                new ListResult<>(
                        List.of(ProtocolVersion.TLS10),
                        TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS.name());
        ListResult<ProtocolVersion> protVer2 =
                new ListResult<>(
                        Arrays.asList(ProtocolVersion.TLS10, ProtocolVersion.DTLS12),
                        "SUPPORTED_PROTOCOL_VERSIONS");
        report1.putResult(property, protVer1);
        report2.putResult(property, protVer2);

        // normal values
        Requirement<TestReport> requirementGreater =
                new PropertyComparatorRequirement<>(
                        PropertyComparatorRequirement.Operator.GREATER, property, 2);
        Requirement<TestReport> requirementSmaller =
                new PropertyComparatorRequirement<>(
                        PropertyComparatorRequirement.Operator.SMALLER, property, 2);
        Requirement<TestReport> requirementEqual =
                new PropertyComparatorRequirement<>(
                        PropertyComparatorRequirement.Operator.EQUAL, property, 2);

        // illegal
        Requirement<TestReport> requirementNegative =
                new PropertyComparatorRequirement<>(
                        PropertyComparatorRequirement.Operator.EQUAL, property, -2);
        Requirement<TestReport> requirementNullValue =
                new PropertyComparatorRequirement<>(
                        PropertyComparatorRequirement.Operator.EQUAL, property, null);

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
        assertFalse(requirementNullValue.evaluate(report2));
    }
}
