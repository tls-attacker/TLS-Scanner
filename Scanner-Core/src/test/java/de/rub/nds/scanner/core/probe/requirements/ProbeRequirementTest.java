/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.constants.ProbeType;
import org.junit.jupiter.api.Test;

public class ProbeRequirementTest {

    private enum TestProbeType implements ProbeType {
        TEST_PROBE_TYPE;

        @Override
        public String getName() {
            return name();
        }
    }

    @Test
    public void testProbeRequirement() {
        TestReport report = new TestReport();
        TestProbeType probe = TestProbeType.TEST_PROBE_TYPE;

        ProbeRequirement<TestReport> requirement = new ProbeRequirement<>();
        assertTrue(requirement.evaluate(report));

        requirement = new ProbeRequirement<>(new TestProbeType[0]);
        assertTrue(requirement.evaluate(report));

        requirement = new ProbeRequirement<>(probe);
        assertArrayEquals(
                requirement.getParameters().toArray(new ProbeType[0]), new TestProbeType[] {probe});
        assertFalse(requirement.evaluate(report));

        report.markProbeAsExecuted(probe);
        assertTrue(requirement.evaluate(report));
    }
}
