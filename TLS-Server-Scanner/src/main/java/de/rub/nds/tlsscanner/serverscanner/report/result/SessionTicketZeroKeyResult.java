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
