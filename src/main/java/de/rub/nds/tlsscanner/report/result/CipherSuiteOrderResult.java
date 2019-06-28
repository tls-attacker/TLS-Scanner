/**
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
