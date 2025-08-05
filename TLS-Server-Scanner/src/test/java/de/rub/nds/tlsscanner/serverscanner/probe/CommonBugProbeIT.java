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
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class CommonBugProbeIT extends AbstractProbeIT {

    public CommonBugProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new CommonBugProbe(configSelector, parallelExecutor);
    }

    @Override
    protected void prepareReport() {}

    @Override
    protected boolean executedAsPlanned() {
        return verifyProperty(TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE,
                        TestResults.FALSE);
    }
}
