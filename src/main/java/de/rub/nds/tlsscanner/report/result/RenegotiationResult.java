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
public class RenegotiationResult extends ProbeResult {

    private Boolean secureRenegotiation;
    private Boolean insecureRenegotiation;

    public RenegotiationResult(Boolean secureRenegotiation, Boolean insecureRenegotiation) {
        super(ProbeType.RENEGOTIATION);
        this.secureRenegotiation = secureRenegotiation;
        this.insecureRenegotiation = insecureRenegotiation;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setSupportsClientSideSecureRenegotiation(secureRenegotiation);
        report.setSupportsClientSideInsecureRenegotiation(insecureRenegotiation);
    }

}
