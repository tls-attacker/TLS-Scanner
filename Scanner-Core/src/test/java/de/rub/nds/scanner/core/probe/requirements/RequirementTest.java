/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.probe.requirements;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.report.ScanReport;
import org.junit.Test;

public class RequirementTest {

    @Test
    public void basicFunctionalityRequirementTest() {
        assertEquals(new Requirement().next, Requirement.NO_REQUIREMENT);

        // evaluation
        assertTrue(Requirement.NO_REQUIREMENT.evaluate(new TestReport()));
        assertTrue(new Requirement().evaluate(new TestReport()));
    }

    /**
     * Implementation of ScanReport
     */
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
