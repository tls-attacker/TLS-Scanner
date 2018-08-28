/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CipherSuiteOrderResult extends ProbeResult {
    
    private Boolean enforced;
    
    public CipherSuiteOrderResult(Boolean enforced) {
        super(ProbeType.CIPHERSUITE_ORDER);
        this.enforced = enforced;
    }
    
    @Override
    public void mergeData(SiteReport report) {
        report.setEnforcesCipherSuiteOrdering(enforced);
    }
}
