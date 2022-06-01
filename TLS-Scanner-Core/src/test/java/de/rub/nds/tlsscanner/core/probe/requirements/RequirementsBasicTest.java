package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.report.ScanReport;

public class RequirementsBasicTest {

	// TODO combination of reqs etc
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
