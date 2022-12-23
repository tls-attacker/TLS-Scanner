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
public class CertificateProbeIT extends AbstractProbeIT {

    public CertificateProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected boolean executedAsPlanned() {
        return report.getCertificateChainList().size() == 1
                && report.getEcdsaPkGroupsStatic().size() == 0
                && report.getEcdsaPkGroupsEphemeral().size() == 0
                && report.getEcdsaPkGroupsTls13().size() == 0
                && report.getEcdsaSigGroupsStatic().size() == 0
                && report.getEcdsaSigGroupsEphemeral().size() == 0
                && report.getEcdsaSigGroupsTls13().size() == 0;
    }

    @Override
    protected ProbeType getTestProbe() {
        return TlsProbeType.CERTIFICATE;
    }

    @Override
    protected List<ProbeType> getRequiredProbes() {
        return Arrays.asList(TlsProbeType.PROTOCOL_VERSION, TlsProbeType.CIPHER_SUITE);
    }
}
