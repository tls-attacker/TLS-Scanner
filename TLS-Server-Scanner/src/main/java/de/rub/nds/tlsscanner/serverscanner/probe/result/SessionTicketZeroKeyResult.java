/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class SessionTicketZeroKeyResult extends ProbeResult<ServerReport> {

    private final TestResult hasDecryptableMasterSecret;
    private final TestResult hasGnuTlsMagicBytes;

    public SessionTicketZeroKeyResult(TestResult hasDecryptableMasterSecret, TestResult hasGnuTlsMagicBytes) {
        super(TlsProbeType.SESSION_TICKET_ZERO_KEY);
        this.hasDecryptableMasterSecret = hasDecryptableMasterSecret;
        this.hasGnuTlsMagicBytes = hasGnuTlsMagicBytes;

    }

    @Override
    protected void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY, this.hasDecryptableMasterSecret);
        report.putResult(TlsAnalyzedProperty.HAS_GNU_TLS_MAGIC_BYTES, this.hasGnuTlsMagicBytes);
    }

}
