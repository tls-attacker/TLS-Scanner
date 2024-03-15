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

public class OrRequirementTest {

    @Test
    public void testOrRequirement() {
        TestReport report = new TestReport();
        Requirement<TestReport>
                requirement1 =
                        new OrRequirement<TestReport>(
                                List.of(
                                        new FulfilledRequirement<>(),
                                        new FulfilledRequirement<>())),
                requirement2 =
                        new OrRequirement<TestReport>(
                                List.of(
                                        new FulfilledRequirement<>(),
                                        new UnfulfillableRequirement<>())),
                requirement3 =
                        new OrRequirement<TestReport>(
                                List.of(
                                        new UnfulfillableRequirement<>(),
                                        new FulfilledRequirement<>())),
                requirement4 =
                        new OrRequirement<TestReport>(
                                List.of(
                                        new UnfulfillableRequirement<>(),
                                        new UnfulfillableRequirement<>()));
        assertTrue(requirement1.evaluate(report));
        assertTrue(requirement2.evaluate(report));
        assertTrue(requirement3.evaluate(report));
        assertFalse(requirement4.evaluate(report));

        OrRequirement<TestReport> combined = requirement1.or(requirement2);
        assertEquals(4, combined.getContainedRequirements().size());
    }
}
