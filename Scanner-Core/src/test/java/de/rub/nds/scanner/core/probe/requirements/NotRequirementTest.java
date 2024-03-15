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

import org.junit.jupiter.api.Test;

public class NotRequirementTest {

    @Test
    public void testNotRequirement() {
        TestReport report = new TestReport();
        Requirement<TestReport>
                requirement1 = new NotRequirement<TestReport>(new UnfulfillableRequirement<>()),
                requirement2 = new NotRequirement<TestReport>(new FulfilledRequirement<>());
        assertTrue(requirement1.evaluate(report));
        assertFalse(requirement2.evaluate(report));
        assertInstanceOf(UnfulfillableRequirement.class, requirement1.not());
        assertInstanceOf(FulfilledRequirement.class, requirement2.not());
    }
}
