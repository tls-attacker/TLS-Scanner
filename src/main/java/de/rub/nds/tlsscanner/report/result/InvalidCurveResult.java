/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.probe.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class InvalidCurveResult extends ProbeResult {

    private final Boolean vulnerableClassic;
    private final Boolean vulnerableEphemeral;

    public InvalidCurveResult(Boolean vulnerableClassic, Boolean vulnerableEphemeral) {
        super(ProbeType.INVALID_CURVE);
        this.vulnerableClassic = vulnerableClassic;
        this.vulnerableEphemeral = vulnerableEphemeral;
    }

    @Override
    public void merge(SiteReport report) {
        report.setInvalidCurveVulnerable(vulnerableClassic);
        report.setInvalidCurveEphermaralVulnerable(vulnerableEphemeral);
    }

}
