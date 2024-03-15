/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

public class AndRequirementTest {

    @Test
    public void testAndRequirement() {
        TestReport report = new TestReport();
        Requirement<TestReport>
                requirement1 =
                        new AndRequirement<TestReport>(
                                List.of(
                                        new FulfilledRequirement<>(),
                                        new FulfilledRequirement<>())),
                requirement2 =
                        new AndRequirement<TestReport>(
                                List.of(
                                        new FulfilledRequirement<>(),
                                        new UnfulfillableRequirement<>())),
                requirement3 =
                        new AndRequirement<TestReport>(
                                List.of(
                                        new UnfulfillableRequirement<>(),
                                        new FulfilledRequirement<>())),
                requirement4 =
                        new AndRequirement<TestReport>(
                                List.of(
                                        new UnfulfillableRequirement<>(),
                                        new UnfulfillableRequirement<>()));
        assertTrue(requirement1.evaluate(report));
        assertFalse(requirement2.evaluate(report));
        assertFalse(requirement3.evaluate(report));
        assertFalse(requirement4.evaluate(report));

        AndRequirement<TestReport> combined = requirement1.and(requirement2);
        assertEquals(4, combined.getContainedRequirements().size());
    }
}
