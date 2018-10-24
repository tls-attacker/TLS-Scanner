/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class LogjamAfterprobe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        if (report.getCipherSuites() != null) {
            for (CipherSuite suite : report.getCipherSuites()) {
                if (suite.name().contains("DH_anon_EXPORT") || suite.name().contains("DH_DSS_EXPORT") || suite.name().contains("DH_RSA_EXPORT") || suite.name().contains("DHE_DSS_EXPORT") || suite.name().contains("DHE_RSA_EXPORT")) {
                    report.setLogjamVulnerable(Boolean.TRUE);
                    return;
                }
            }
            report.setLogjamVulnerable(Boolean.FALSE);
        }
    }
}
