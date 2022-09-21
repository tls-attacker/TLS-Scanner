/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import org.junit.jupiter.api.Test;

public class SiteReportPrinterTest {

    /**
     * Test of getFullReport method, of class SiteReportPrinter.
     */
    @Test
    public void testPrintEmptyReport() {
        ServerReport report = new ServerReport("somehost", 443);
        for (ScannerDetail detail : ScannerDetail.values()) {
            ServerReportPrinter printer =
                new ServerReportPrinter(report, detail, DefaultPrintingScheme.getDefaultPrintingScheme(true), true);
            printer.getFullReport();
        }
    }

}
