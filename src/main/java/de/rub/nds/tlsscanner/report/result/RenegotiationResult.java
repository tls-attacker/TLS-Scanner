/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
