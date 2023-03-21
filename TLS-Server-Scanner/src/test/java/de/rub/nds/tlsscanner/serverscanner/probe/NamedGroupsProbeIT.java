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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class NamedGroupsProbeIT extends AbstractProbeIT {

    public NamedGroupsProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected boolean executedAsPlanned() {
        List<NamedGroup> expectedGroups =
                Arrays.asList(
                        NamedGroup.SECP384R1,
                        NamedGroup.ECDH_X25519,
                        NamedGroup.SECP256R1,
                        NamedGroup.ECDH_X448,
                        NamedGroup.SECP521R1);
        List<NamedGroup> supportedGroups = report.getSupportedNamedGroups();
        List<NamedGroup> expectedGroupsTls13 =
                Arrays.asList(
                        NamedGroup.SECP384R1,
                        NamedGroup.ECDH_X25519,
                        NamedGroup.SECP256R1,
                        NamedGroup.ECDH_X448,
                        NamedGroup.SECP521R1);
        List<NamedGroup> supportedGroupsTls13 = report.getSupportedTls13Groups();
        return expectedGroups.size() == supportedGroups.size()
                && expectedGroups.containsAll(supportedGroups.stream().collect(Collectors.toList()))
                && expectedGroupsTls13.size() == supportedGroupsTls13.size()
                && expectedGroupsTls13.containsAll(
                        supportedGroupsTls13.stream().collect(Collectors.toList()))
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_EXPLICIT_PRIME_CURVE, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_EXPLICIT_CHAR2_CURVE, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.GROUPS_DEPEND_ON_CIPHER, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY, TestResults.FALSE);
    }

    @Override
    protected ProbeType getTestProbe() {
        return TlsProbeType.NAMED_GROUPS;
    }

    @Override
    protected List<ProbeType> getRequiredProbes() {
        return Arrays.asList(
                TlsProbeType.PROTOCOL_VERSION, TlsProbeType.CIPHER_SUITE, TlsProbeType.CERTIFICATE);
    }
}
