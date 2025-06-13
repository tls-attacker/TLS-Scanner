/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.FulfilledRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class CipherSuiteOrderProbe extends TlsServerProbe {

    private TestResult enforced = TestResults.COULD_NOT_TEST;
    private TestResult avoidsWeakCipherSuites = TestResults.COULD_NOT_TEST;

    public CipherSuiteOrderProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CIPHER_SUITE_ORDER, configSelector);
        register(
                TlsAnalyzedProperty.ENFORCES_CS_ORDERING,
                TlsAnalyzedProperty.AVOIDS_WEAK_CIPHER_SUITES);
    }

    @Override
    protected void executeTest() {
        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        CipherSuite firstSelectedCipherSuite = getSelectedCipherSuite(toTestList);
        Collections.reverse(toTestList);
        CipherSuite secondSelectedCipherSuite = getSelectedCipherSuite(toTestList);
        enforced =
                (firstSelectedCipherSuite == secondSelectedCipherSuite)
                        ? TestResults.TRUE
                        : TestResults.FALSE;

        List<CipherSuite> toTestListForWeakCS = new LinkedList<>();
        toTestListForWeakCS.addAll(
                Arrays.asList(
                        // We define "weak" cipher suites as:
                        // Weak CS = cipher suites that are not forbidden but SHOULD NOT be used
                        // according to RFC 9325 - DHE with GCM/CCM
                        CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
                        CipherSuite.TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
                        CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                        CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
                        CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_CCM,
                        CipherSuite.TLS_RSA_WITH_AES_128_CCM_8,
                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_256_CCM,
                        CipherSuite.TLS_RSA_WITH_AES_256_CCM_8,
                        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384,
                        CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                        CipherSuite.TLS_RSA_WITH_DES_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA,
                        CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
                        CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
                        CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
                        CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
                        CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
                        CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
                        CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
                        CipherSuite.TLS_DH_anon_WITH_DES_CBC_SHA,
                        CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA,
                        CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
                        CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
                        CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
                        CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
                        CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
                        CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
                        CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
                        CipherSuite.TLS_DH_DSS_WITH_DES_CBC_SHA,
                        CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA,
                        CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
                        CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
                        CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
                        CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                        CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
                        CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                        CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                        CipherSuite.TLS_DH_RSA_WITH_DES_CBC_SHA,
                        CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA,
                        CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
                        CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
                        CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
                        CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
                        CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
                        CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                        CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
                        CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
                        CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
                        CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
                        CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA,
                        CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA,
                        CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
                        CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                        CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
                        CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_DES_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA,
                        // This cipher suite MUST be preferred by servers according to RFC 9325,
                        // even if it is not the first proposal:
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
        CipherSuite thirdSelectedCipherSuite = getSelectedCipherSuite(toTestListForWeakCS);
        avoidsWeakCipherSuites =
                (thirdSelectedCipherSuite == CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
                        ? TestResults.TRUE
                        : TestResults.FALSE;
    }

    public CipherSuite getSelectedCipherSuite(List<CipherSuite> toTestList) {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setDefaultClientSupportedCipherSuites(toTestList);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getTlsContext().getSelectedCipherSuite();
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new FulfilledRequirement<>();
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.ENFORCES_CS_ORDERING, enforced);
        put(TlsAnalyzedProperty.AVOIDS_WEAK_CIPHER_SUITES, avoidsWeakCipherSuites);
    }
}
