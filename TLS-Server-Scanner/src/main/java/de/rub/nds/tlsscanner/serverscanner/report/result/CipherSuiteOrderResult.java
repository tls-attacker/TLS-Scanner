/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CipherSuiteOrderResult extends ProbeResult {

    private TestResult enforced;

    public CipherSuiteOrderResult(TestResult enforced) {
        super(ProbeType.CIPHERSUITE_ORDER);
        this.enforced = enforced;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.ENFOCRES_CS_ORDERING, enforced);
    }
}
