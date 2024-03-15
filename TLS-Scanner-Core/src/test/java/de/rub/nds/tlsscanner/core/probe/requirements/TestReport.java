/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

/** Implementation of ScanReport for tests */
public class TestReport extends TlsScanReport<TestReport> {
    private static final long serialVersionUID = 1L;

    public TestReport() {
        super();
    }

    @Override
    public String getFullReport(ScannerDetail detail, boolean printColorful) {
        return null;
    }
}
