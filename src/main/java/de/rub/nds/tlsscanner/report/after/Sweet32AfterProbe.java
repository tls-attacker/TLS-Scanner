/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class Sweet32AfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        if (report.getCipherSuites() != null) {
            for (CipherSuite suite : report.getCipherSuites()) {
                if (suite.name().contains("3DES") || suite.name().contains("IDEA")) {
                    report.setSweet32Vulnerable(Boolean.TRUE);
                    return;
                }
            }
            report.setSweet32Vulnerable(Boolean.FALSE);
        }
    }
}
