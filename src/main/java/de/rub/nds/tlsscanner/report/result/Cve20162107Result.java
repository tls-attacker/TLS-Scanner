/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.probe.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class Cve20162107Result extends ProbeResult {

    private Boolean vulnerable;

    public Cve20162107Result(Boolean vulnerable) {
        super(ProbeType.BLEICHENBACHER);
        this.vulnerable = vulnerable;
    }

    @Override
    public void merge(SiteReport report) {
        report.setBleichenbacherVulnerable(vulnerable);
    }

}
