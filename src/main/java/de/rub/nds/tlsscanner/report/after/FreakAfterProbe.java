/**
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

public class FreakAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        Boolean vulnerable = null;
        if (report.getCipherSuites() != null) {
            for (CipherSuite suite : report.getCipherSuites()) {
                if (suite.name().contains("RSA_EXPORT")) {
                    vulnerable = true;
                }
            }
            if (vulnerable != Boolean.TRUE) {
                vulnerable = false;
            }
        }
        report.setFreakVulnerable(vulnerable);
    }
}
