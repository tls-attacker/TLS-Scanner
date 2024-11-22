/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class CompressionsProbeIT extends AbstractProbeIT {

    public CompressionsProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new CompressionsProbe(configSelector, parallelExecutor);
    }

    @Override
    protected void prepareReport() {}

    @Override
    protected boolean executedAsPlanned() {
        List<CompressionMethod> expectedCompressions = Arrays.asList(CompressionMethod.NULL);
        List<CompressionMethod> supportedCompressions = report.getSupportedCompressionMethods();
        return expectedCompressions.size() == supportedCompressions.size()
                && expectedCompressions.containsAll(
                        supportedCompressions.stream().collect(Collectors.toList()))
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.VULNERABLE_TO_CRIME, TestResults.FALSE);
    }
}
