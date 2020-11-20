/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;

public class SessionTicketZeroKeyResult extends ProbeResult {

    private TestResult hasDecryptableMasterSecret;
    private TestResult hasGnuTlsMagicBytes;

    public SessionTicketZeroKeyResult(TestResult hasDecryptableMasterSecret, TestResult hasGnuTlsMagicBytes) {
        super(ProbeType.SESSION_TICKET_ZERO_KEY);
        this.hasDecryptableMasterSecret = hasDecryptableMasterSecret;
        this.hasGnuTlsMagicBytes = hasGnuTlsMagicBytes;

    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY, this.hasDecryptableMasterSecret);
        report.putResult(AnalyzedProperty.HAS_GNU_TLS_MAGIC_BYTES, this.hasGnuTlsMagicBytes);
    }

}