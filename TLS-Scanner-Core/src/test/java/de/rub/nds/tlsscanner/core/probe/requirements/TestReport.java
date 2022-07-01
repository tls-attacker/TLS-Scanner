/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

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