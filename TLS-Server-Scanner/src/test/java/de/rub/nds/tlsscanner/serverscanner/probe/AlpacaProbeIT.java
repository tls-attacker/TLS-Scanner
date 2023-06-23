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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class AlpacaProbeIT extends AbstractProbeIT {

    public AlpacaProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new AlpacaProbe(configSelector, parallelExecutor);
    }

    @Override
    protected void prepareReport() {
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_EXTENSIONS, Arrays.asList(ExtensionType.ALPN));
    }

    @Override
    protected boolean executedAsPlanned() {
        return verifyProperty(TlsAnalyzedProperty.STRICT_SNI, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.STRICT_ALPN, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.ALPACA_MITIGATED, TestResults.FALSE);
    }
}
