/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.RaccoonAttackResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

public class RaccoonAttackProbe extends TlsProbe {

    private boolean supportsSSLv3;

    private List<VersionSuiteListPair> suitePairList;

    public RaccoonAttackProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RACCOON_ATTACK, scannerConfig, 0);
    }

    @Override
    public ProbeResult executeTest() {
        Config config = scannerConfig.createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setEnforceSettings(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddEllipticCurveExtension(false);
        config.setAddECPointFormatExtension(false);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddRenegotiationInfoExtension(true);
        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterFatal(true);

        List<CipherSuite> staticDhCipherSuites = new LinkedList<>();
        List<CipherSuite> ephemeralDhCipherSuites = new LinkedList<>();

        BigInteger reusedDheModulus = null; // Its not just a reused modulus -
                                            // its a reused modulus for a reused
                                            // public key...
        BigInteger staticDhModulus = null;
        Boolean supportsSha384Prf = false;
        Boolean supportsLegacyPrf = false;
        Boolean supportsSha256Prf = false;

        for (VersionSuiteListPair versionSuitePair : suitePairList) {
            for (CipherSuite suite : versionSuitePair.getCiphersuiteList()) {
                KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(suite);
                if (keyExchangeAlgorithm == KeyExchangeAlgorithm.DH_DSS
                        || keyExchangeAlgorithm == KeyExchangeAlgorithm.DH_RSA) {
                    staticDhCipherSuites.add(suite);
                }

                if (keyExchangeAlgorithm == KeyExchangeAlgorithm.DHE_DSS
                        || keyExchangeAlgorithm == KeyExchangeAlgorithm.DHE_PSK
                        || keyExchangeAlgorithm == KeyExchangeAlgorithm.DHE_RSA) {
                    ephemeralDhCipherSuites.add(suite);
                    if (AlgorithmResolver.getPRFAlgorithm(versionSuitePair.getVersion(), suite) == PRFAlgorithm.TLS_PRF_SHA256) {
                        supportsSha256Prf = true;
                    }
                    if (AlgorithmResolver.getPRFAlgorithm(versionSuitePair.getVersion(), suite) == PRFAlgorithm.TLS_PRF_SHA384) {
                        supportsSha384Prf = true;
                    }
                    if (AlgorithmResolver.getPRFAlgorithm(versionSuitePair.getVersion(), suite) == PRFAlgorithm.TLS_PRF_LEGACY) {
                        supportsLegacyPrf = true;
                    }
                }
            }

        }
        config.setDefaultClientSupportedCiphersuites(staticDhCipherSuites);
        State state = new State(config);
        try {
            executeState(state);
            if (state.getTlsContext().getSelectedCipherSuite() != null) {
                KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(state
                        .getTlsContext().getSelectedCipherSuite());
                if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())
                        && keyExchangeAlgorithm == KeyExchangeAlgorithm.DH_DSS
                        || keyExchangeAlgorithm == KeyExchangeAlgorithm.DH_RSA) {
                    // static dh is supported
                    staticDhModulus = state.getTlsContext().getServerDhModulus();
                }
            }
            config.setDefaultClientSupportedCiphersuites(ephemeralDhCipherSuites);
            executeState(state);

            BigInteger firstPk = null;
            if (state.getTlsContext().getSelectedCipherSuite() != null) {

                KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(state
                        .getTlsContext().getSelectedCipherSuite());
                if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())
                        && keyExchangeAlgorithm.isKeyExchangeDh()
                        && state.getTlsContext().getSelectedCipherSuite().isEphemeral()) {
                    // static dh is supported
                    firstPk = state.getTlsContext().getServerDhPublicKey();
                }
            }
            executeState(state);
            BigInteger secondPk = null;
            if (state.getTlsContext().getSelectedCipherSuite() != null) {
                KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(state
                        .getTlsContext().getSelectedCipherSuite());
                if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())
                        && keyExchangeAlgorithm.isKeyExchangeDh()
                        && state.getTlsContext().getSelectedCipherSuite().isEphemeral()) {
                    // static dh is supported
                    secondPk = state.getTlsContext().getServerDhPublicKey();
                }
            }
            if (firstPk != null && secondPk != null && firstPk.equals(secondPk)) {
                reusedDheModulus = state.getTlsContext().getServerDhModulus();
            }
            return new RaccoonAttackResult(reusedDheModulus, staticDhModulus, supportsSha384Prf, supportsSha256Prf,
                    supportsLegacyPrf, supportsSSLv3);
        } catch (Exception E) {
            LOGGER.warn("Could not execute RaccoonAttackProbe", E);
        }
        return new RaccoonAttackResult();
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.TRUE
                && report.getVersionSuitePairs() != null) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new RaccoonAttackResult();
    }

    @Override
    public void adjustConfig(SiteReport report) {
        TestResult supportsSsl3 = report.getResult(AnalyzedProperty.SUPPORTS_SSL_3);
        if (supportsSsl3 == TestResult.TRUE) {
            supportsSSLv3 = true;
        } else {
            // Maybe this is not TestResult.FALSE - but anyways it would not be
            // helpful
            supportsSSLv3 = false;
        }
        suitePairList = report.getVersionSuitePairs();
    }

}
