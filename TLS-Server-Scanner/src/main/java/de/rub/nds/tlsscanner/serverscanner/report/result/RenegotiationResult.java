/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author robert
 */
public class RenegotiationResult extends ProbeResult {

    private TestResult secureRenegotiation;
    private TestResult insecureRenegotiation;

    public RenegotiationResult(TestResult secureRenegotiation, TestResult insecureRenegotiation) {
        super(ProbeType.RENEGOTIATION);
        this.secureRenegotiation = secureRenegotiation;
        this.insecureRenegotiation = insecureRenegotiation;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION, secureRenegotiation);
        report.putResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION, insecureRenegotiation);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK, insecureRenegotiation);
    }

}
