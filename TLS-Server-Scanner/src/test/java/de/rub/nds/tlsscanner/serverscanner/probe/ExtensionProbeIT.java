/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class ExtensionProbeIT extends AbstractProbeIT {

    public ExtensionProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected boolean executedAsPlanned() {
        List<ExtensionType> expectedExtensions =
                Arrays.asList(
                        ExtensionType.MAX_FRAGMENT_LENGTH,
                        ExtensionType.SUPPORTED_VERSIONS,
                        ExtensionType.EXTENDED_MASTER_SECRET,
                        ExtensionType.SESSION_TICKET,
                        ExtensionType.RENEGOTIATION_INFO,
                        ExtensionType.ELLIPTIC_CURVES,
                        ExtensionType.KEY_SHARE,
                        ExtensionType.ENCRYPT_THEN_MAC);
        List<ExtensionType> supportedExtensions = report.getSupportedExtensions();
        return expectedExtensions.size() == supportedExtensions.size()
                && expectedExtensions.containsAll(
                        supportedExtensions.stream().collect(Collectors.toList()))
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, TestResults.TRUE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
                        TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKETS, TestResults.TRUE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2,
                        TestResults.FALSE);
    }

    @Override
    protected ProbeType getTestProbe() {
        return TlsProbeType.EXTENSIONS;
    }

    @Override
    protected List<ProbeType> getRequiredProbes() {
        return Arrays.asList(TlsProbeType.PROTOCOL_VERSION);
    }
}
