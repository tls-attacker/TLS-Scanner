/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.report;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.report.ReportCreator;
import de.rub.nds.scanner.core.report.container.HeadlineContainer;
import de.rub.nds.scanner.core.report.container.ListContainer;
import de.rub.nds.scanner.core.report.container.ReportContainer;
import de.rub.nds.scanner.core.report.container.TextContainer;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.CipherSuiteGrade;
import de.rub.nds.tlsscanner.core.report.CipherSuiteRater;

public class ClientContainerReportCreator extends ReportCreator {

    public ClientContainerReportCreator() {
        super(DefaultPrintingScheme.getDefaultPrintingScheme());
    }

    public ReportContainer createReport(ClientReport report) {
        ListContainer rootContainer = new ListContainer();
        addCipherSuiteContainer(rootContainer, report);
        addProtocolVersionContainer(rootContainer, report);
        return rootContainer;
    }

    @SuppressWarnings("unchecked")
    private void addCipherSuiteContainer(ListContainer rootContainer, ClientReport report) {
        rootContainer.add(new HeadlineContainer("Supported Cipher suites"));
        ListContainer listContainer = new ListContainer();
        for (CipherSuite suite : ((ListResult<CipherSuite>) report
            .getListResult(TlsAnalyzedProperty.LIST_ADVERTISED_CIPHERSUITES.name())).getList()) {
            listContainer.add(new TextContainer(suite.name(), getColorForCipherSuite(suite)));
        }
        rootContainer.add(listContainer);
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

    private void addProtocolVersionContainer(ListContainer rootContainer, ClientReport report) {
        rootContainer.add(new HeadlineContainer("Supported Versions"));
        rootContainer.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_SSL_2, report));
        rootContainer.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_SSL_3, report));
        rootContainer.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, report));
        rootContainer.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, report));
        rootContainer.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, report));
        rootContainer.add(createKeyValueContainer(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, report));
    }
}
