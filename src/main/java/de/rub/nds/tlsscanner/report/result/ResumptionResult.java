/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author robert
 */
public class ResumptionResult extends ProbeResult {

    private Boolean supportsResumption;

    public ResumptionResult(Boolean supportsResumption) {
        super(ProbeType.RESUMPTION);
        this.supportsResumption = supportsResumption;
    }

    @Override
    public void merge(SiteReport report) {
        report.setSupportsSessionIds(supportsResumption);
    }

}
