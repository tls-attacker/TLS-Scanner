package de.rub.nds.tlsscanner.clientscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;

public class TlsFallbackScsvAfterProbe extends AfterProbe<ClientReport> {

    @Override
    public void analyze(ClientReport report) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV, report.getSupportedCipherSuites().contains(CipherSuite.TLS_FALLBACK_SCSV));
    }
}
