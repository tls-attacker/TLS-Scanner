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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class NamedGroupsProbeIT extends AbstractProbeIT {

    public NamedGroupsProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new NamedGroupsProbe(configSelector, parallelExecutor);
    }

    @Override
    protected void prepareReport() {
        Set<CipherSuite> supportedCiphers = new HashSet<>();
        supportedCiphers.addAll(
                Arrays.asList(
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_AES_128_GCM_SHA256));
        report.putResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, supportedCiphers);
        report.putResult(TlsAnalyzedProperty.STATIC_ECDSA_PK_GROUPS, new LinkedList<>());
        report.putResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_PK_GROUPS, new LinkedList<>());
        report.putResult(TlsAnalyzedProperty.STATIC_ECDSA_SIG_GROUPS, new LinkedList<>());
        report.putResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_SIG_GROUPS, new LinkedList<>());
        report.putResult(TlsAnalyzedProperty.TLS13_ECDSA_PK_GROUPS, new LinkedList<>());
        report.putResult(TlsAnalyzedProperty.TLS13_ECDSA_SIG_GROUPS, new LinkedList<>());
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
}
