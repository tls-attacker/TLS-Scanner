/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class DrownAfterProbe extends AfterProbe {
    
    @Override
    public void analyze(SiteReport report) {
        if (report.getSupportsSsl2() == Boolean.TRUE) {
            report.setDrownVulnerable(Boolean.TRUE);
        }
    }
    
}
