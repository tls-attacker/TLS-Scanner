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
