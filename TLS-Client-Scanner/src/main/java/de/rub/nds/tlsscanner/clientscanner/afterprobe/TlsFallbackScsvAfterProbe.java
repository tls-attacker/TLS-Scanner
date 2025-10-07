/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.List;

public class TlsFallbackScsvAfterProbe extends AfterProbe<ClientReport> {

    @Override
    public void analyze(ClientReport report) {
        List<CipherSuite> clientAdvertisedCipherSuites = report.getClientAdvertisedCipherSuites();

        boolean supported =
                clientAdvertisedCipherSuites != null
                        && clientAdvertisedCipherSuites.contains(CipherSuite.TLS_FALLBACK_SCSV);

        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV, supported);
    }
}
