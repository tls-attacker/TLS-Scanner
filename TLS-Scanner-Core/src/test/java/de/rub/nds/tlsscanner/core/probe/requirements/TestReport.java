package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.tlsscanner.core.report.TlsReport;

/**
 * Implementation of ScanReport for tests
 */
public class TestReport extends TlsReport {
	private static final long serialVersionUID = 1L;

	public TestReport() {
		super();
	}

	@Override
	public String getFullReport(ScannerDetail detail, boolean printColorful) {
		return null;
	}
}