/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.report;

import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.report.container.HeadlineContainer;
import de.rub.nds.scanner.core.report.container.ListContainer;
import de.rub.nds.scanner.core.report.container.ReportContainer;
import de.rub.nds.scanner.core.report.container.TextContainer;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.core.report.CipherSuiteGrade;
import de.rub.nds.tlsscanner.core.report.CipherSuiteRater;

public class ClientContainerReportCreator {

    public ReportContainer createReport(ClientReport report) {
        ListContainer rootContainer = new ListContainer();
        addCipherSuiteContainer(rootContainer, report);

        return rootContainer;
    }

    private void addCipherSuiteContainer(ListContainer rootContainer, ClientReport report) {
        rootContainer.add(new HeadlineContainer("Supported Cipher suites"));
        ListContainer listContainer = new ListContainer();
        for (CipherSuite suite : report.getAdvertisedCipherSuites()) {
            listContainer.add(new TextContainer(suite.name(), getColorForCipherSuite(suite)));
        }
    }

    private AnsiColor getColorForCipherSuite(CipherSuite suite) {
        CipherSuiteGrade grade = CipherSuiteRater.getGrade(suite);
        switch (grade) {
            case GOOD:
                return AnsiColor.GREEN;
            case LOW:
                return AnsiColor.RED;
            case MEDIUM:
                return AnsiColor.YELLOW;
            default:
                return AnsiColor.DEFAULT_COLOR;
        }
    }
}
