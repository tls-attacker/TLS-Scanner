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
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class NamedCurvesOrderProbeIT extends AbstractProbeIT {

    public NamedCurvesOrderProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected boolean executedAsPlanned() {
        return verifyProperty(TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING, TestResults.TRUE);
    }

    @Override
    protected ProbeType getTestProbe() {
        return TlsProbeType.NAMED_GROUPS_ORDER;
    }

    @Override
    protected List<ProbeType> getRequiredProbes() {
        return Arrays.asList(
                TlsProbeType.PROTOCOL_VERSION,
                TlsProbeType.CIPHER_SUITE,
                TlsProbeType.CERTIFICATE,
                TlsProbeType.NAMED_GROUPS);
    }
}
