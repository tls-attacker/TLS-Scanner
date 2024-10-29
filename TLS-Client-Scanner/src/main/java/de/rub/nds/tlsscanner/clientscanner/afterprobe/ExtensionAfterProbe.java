package de.rub.nds.tlsscanner.clientscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;

import java.util.List;
import java.util.Set;

public class ExtensionAfterProbe extends AfterProbe<ClientReport> {

    static final TlsAnalyzedProperty[] ANALYZED_PROPERTIES = {
            TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
            TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
            TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
            TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_EXTENSION,
            TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST,
            TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2,
            TlsAnalyzedProperty.SUPPORTED_EXTENSIONS};

    @Override
    public void analyze(ClientReport report) {
        try {
            Set<ExtensionType> extensions = report.getClientAdvertisedExtensions();
            if (extensions.isEmpty()) {
                for (TlsAnalyzedProperty analyzedProperty : ANALYZED_PROPERTIES) {
                    report.putResult(analyzedProperty, TestResults.COULD_NOT_TEST);
                }
                return;
            }
            report.putResult(TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, extensions.contains(ExtensionType.EXTENDED_MASTER_SECRET));
            report.putResult(TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, extensions.contains(ExtensionType.ENCRYPT_THEN_MAC));
            report.putResult(TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, extensions.contains(ExtensionType.RENEGOTIATION_INFO));
            report.putResult(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_EXTENSION, extensions.contains(ExtensionType.SESSION_TICKET));
            report.putResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST, extensions.contains(ExtensionType.STATUS_REQUEST));
            report.putResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2, extensions.contains(ExtensionType.STATUS_REQUEST_V2));
            report.putResult(TlsAnalyzedProperty.SUPPORTED_EXTENSIONS, List.copyOf(extensions));
        } catch (Exception e) {
            for (TlsAnalyzedProperty analyzedProperty : ANALYZED_PROPERTIES) {
                report.putResult(analyzedProperty, TestResults.ERROR_DURING_TEST);
            }
        }
    }
}
