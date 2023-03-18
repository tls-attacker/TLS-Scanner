/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.report.ScanReport;
import org.junit.jupiter.api.Test;

public class RequirementTest {

    @Test
    public void basicFunctionalityRequirementTest() {
        assertEquals(new BaseRequirement().next, Requirement.NO_REQUIREMENT);

        assertTrue(Requirement.NO_REQUIREMENT.evaluate(new TestReport()));
        assertTrue(new BaseRequirement().evaluate(new TestReport()));
    }

    /** Implementation of ScanReport */
    protected class TestReport extends ScanReport {
        private static final long serialVersionUID = 1L;

        public TestReport() {
            super();
        }

        @Override
        public String getFullReport(ScannerDetail detail, boolean printColorful) {
            return null;
        }
    }
}
