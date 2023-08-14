/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import org.junit.jupiter.api.Test;

public class SiteReportPrinterTest {

    /** Test of getFullReport method, of class SiteReportPrinter. */
    @Test
    public void testPrintEmptyReport() {
        ServerReport report = new ServerReport("somehost", 443);
        for (ScannerDetail detail : ScannerDetail.values()) {
            ServerReportPrinter printer =
                    new ServerReportPrinter(
                            report, detail, DefaultPrintingScheme.getDefaultPrintingScheme(), true);
            printer.getFullReport();
        }
    }
}
