/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class HelloRetryProbeIT extends AbstractProbeIT {

    public HelloRetryProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected boolean executedAsPlanned() {
        return report.getHelloRetryRequestSelectedNamedGroup() == NamedGroup.ECDH_X25519
                && verifyProperty(
                        TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, TestResults.TRUE);
    }

    @Override
    protected ProbeType getTestProbe() {
        return TlsProbeType.HELLO_RETRY;
    }

    @Override
    protected List<ProbeType> getRequiredProbes() {
        return Arrays.asList(TlsProbeType.PROTOCOL_VERSION);
    }
}
