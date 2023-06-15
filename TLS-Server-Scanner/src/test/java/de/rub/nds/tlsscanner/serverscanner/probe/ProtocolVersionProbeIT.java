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
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class ProtocolVersionProbeIT extends AbstractProbeIT {

    public ProtocolVersionProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new ProtocolVersionProbe(configSelector, parallelExecutor);
    }

    @Override
    protected void prepareReport() {}

    @Override
    protected boolean executedAsPlanned() {
        List<ProtocolVersion> expectedVersions =
                Arrays.asList(
                        ProtocolVersion.TLS10, ProtocolVersion.TLS11,
                        ProtocolVersion.TLS12, ProtocolVersion.TLS13);
        List<ProtocolVersion> supportedVersions = report.getSupportedProtocolVersions();
        return expectedVersions.size() == supportedVersions.size()
                && expectedVersions.containsAll(
                        supportedVersions.stream().collect(Collectors.toList()));
    }
}
