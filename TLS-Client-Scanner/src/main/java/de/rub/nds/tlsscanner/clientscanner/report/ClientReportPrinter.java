/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.report;

import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.ReportPrinter;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;

public class ClientReportPrinter extends ReportPrinter<ClientReport> {

    public ClientReportPrinter(ScannerDetail detail, PrintingScheme scheme, boolean printColorful,
        ClientReport scanReport) {
        super(detail, scheme, printColorful, scanReport);
    }

    @Override
    public String getFullReport() {
        StringBuilder builder = new StringBuilder();
        appendCipherSuites(builder);
        return builder.toString();
    }

    private void appendCipherSuites(StringBuilder builder) {
        prettyAppendHeading(builder, "Supported CipherSuites");
        for (CipherSuite suite : report.getAdvertisedCipherSuites()) {
            prettyAppend(builder, suite.name());
        }
    }

}
