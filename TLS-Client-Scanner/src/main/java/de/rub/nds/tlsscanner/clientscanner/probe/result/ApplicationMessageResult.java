/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class ApplicationMessageResult extends ProbeResult<ClientReport> {

    private final TestResult sendsApplicationMessage;

    public ApplicationMessageResult(TestResult sendsApplicationMessage) {
        super(TlsProbeType.APPLICATION_MESSAGE);
        this.sendsApplicationMessage = sendsApplicationMessage;
    }

    @Override
    protected void mergeData(ClientReport report) {
        report.putResult(TlsAnalyzedProperty.SENDS_APPLICATION_MESSAGE, sendsApplicationMessage);
    }
}
