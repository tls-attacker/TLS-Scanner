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
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class AlpnProbeIT extends AbstractProbeIT {

    public AlpnProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "-alpn http/1.1");
    }

    @Override
    protected boolean executedAsPlanned() {
        return report.getSupportedAlpns().size() == 1
                && report.getSupportedAlpns().contains("http/1.1");
    }

    @Override
    protected ProbeType getTestProbe() {
        return TlsProbeType.ALPN;
    }

    @Override
    protected List<ProbeType> getRequiredProbes() {
        return Arrays.asList(TlsProbeType.PROTOCOL_VERSION, TlsProbeType.EXTENSIONS);
    }
}
