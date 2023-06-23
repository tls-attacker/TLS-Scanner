/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.report;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.ReportPrinter;

public class ClientReportPrinter extends ReportPrinter<ClientReport> {

    public ClientReportPrinter(
            ClientReport report,
            ScannerDetail detail,
            PrintingScheme scheme,
            boolean printColorful) {
        super(detail, scheme, printColorful, report);
    }

    @Override
    public String getFullReport() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
