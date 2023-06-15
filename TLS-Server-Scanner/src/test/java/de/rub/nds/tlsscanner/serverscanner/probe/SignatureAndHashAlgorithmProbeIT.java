/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class SignatureAndHashAlgorithmProbeIT extends AbstractProbeIT {

    public SignatureAndHashAlgorithmProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new SignatureAndHashAlgorithmProbe(configSelector, parallelExecutor);
    }

    @Override
    protected void prepareReport() {
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                Arrays.asList(
                        ProtocolVersion.TLS10, ProtocolVersion.TLS11,
                        ProtocolVersion.TLS12, ProtocolVersion.TLS13));
    }

    @Override
    protected boolean executedAsPlanned() {
        List<SignatureAndHashAlgorithm> expectedAlgorithms =
                Arrays.asList(
                        SignatureAndHashAlgorithm.RSA_SHA1,
                        SignatureAndHashAlgorithm.RSA_SHA512,
                        SignatureAndHashAlgorithm.RSA_SHA256,
                        SignatureAndHashAlgorithm.RSA_SHA384,
                        SignatureAndHashAlgorithm.RSA_SHA224,
                        SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
                        SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                        SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        List<SignatureAndHashAlgorithm> supportedAlgortihms =
                report.getSupportedSignatureAndHashAlgorithmsSke();
        List<SignatureAndHashAlgorithm> expectedAlgorithmsTls13 =
                Arrays.asList(
                        SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
                        SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                        SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        List<SignatureAndHashAlgorithm> supportedAlgortihmsTls13 =
                report.getSupportedSignatureAndHashAlgorithmsTls13();
        return expectedAlgorithms.size() == supportedAlgortihms.size()
                && expectedAlgorithms.containsAll(
                        supportedAlgortihms.stream().collect(Collectors.toList()))
                && expectedAlgorithmsTls13.size() == supportedAlgortihmsTls13.size()
                && expectedAlgorithmsTls13.containsAll(
                        supportedAlgortihmsTls13.stream().collect(Collectors.toList()));
    }
}
