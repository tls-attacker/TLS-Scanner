/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeServerRsaParametersAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

// see https://www.smacktls.com/smack.pdf section V-D
public class FreakProbe extends TlsProbe<ClientScannerConfig, ClientReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int P_LEN = 256;
    private static final int Q_LEN = 256;
    private static final int MODULUS_LENGTH = P_LEN + Q_LEN;

    private List<CipherSuite> rsaCipherSuites;
    private TestResult vulnerable;

    private Random random = new Random(0); // Fixed random to be deterministic

    public FreakProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.FREAK, scannerConfig);
        super.register(TlsAnalyzedProperty.VULNERABLE_TO_FREAK);
    }

    @Override
    public void executeTest() {
        Config config = scannerConfig.createConfig();
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS12);
        config.setSupportedVersions(ProtocolVersion.SSL3, ProtocolVersion.TLS10, ProtocolVersion.TLS11,
            ProtocolVersion.TLS12);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
        // Set value in config for workflow trace generation - we will set it later back
        config.setDefaultServerSupportedCipherSuites(rsaCipherSuites);

        BigInteger p, q, modulus, publicExponent, privateKey, phi;
        publicExponent = BigInteger.valueOf(65537);
        do {
            p = BigInteger.probablePrime(P_LEN, random);
            q = BigInteger.probablePrime(Q_LEN, random);
            modulus = p.multiply(q);
            phi = p.subtract(BigInteger.ONE);
            BigInteger q1 = q.subtract(BigInteger.ONE);
            phi = phi.multiply(q1);
        } while (!publicExponent.gcd(phi).equals(BigInteger.ONE));
        privateKey = publicExponent.modInverse(phi);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("p: {}", p);
            LOGGER.debug("q: {}", q);
            LOGGER.debug("Modulus(N): {}", modulus);
            LOGGER.debug("phi(N): {}", phi);
            LOGGER.debug("e: {}", publicExponent);
            LOGGER.debug("d: {}", privateKey);
        }
        config.setDefaultServerRSAModulus(modulus);
        config.setDefaultServerRSAPublicKey(publicExponent);
        config.setDefaultServerRSAPrivateKey(privateKey);
        RSAServerKeyExchangeMessage ske = new RSAServerKeyExchangeMessage();
        ske.setModulus(Modifiable.explicit(modulus.toByteArray()));
        ske.setPublicKey(Modifiable.explicit(publicExponent.toByteArray()));
        TlsAction fixKeysAction = new ChangeServerRsaParametersAction(modulus, publicExponent, privateKey);
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HELLO,
            RunningModeType.SERVER);
        trace.addTlsAction(fixKeysAction);
        trace.addTlsAction(
            new ReceiveAction(new RSAClientKeyExchangeMessage(), new ChangeCipherSpecMessage(), new FinishedMessage()));
        config.setDefaultSelectedCipherSuite(rsaCipherSuites.get(0));
        executeState(new State(config, trace));

        HandshakeMessage ckeMessage =
            WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
        if (ckeMessage != null && ckeMessage instanceof RSAClientKeyExchangeMessage) {
            RSAClientKeyExchangeMessage rsaCke = (RSAClientKeyExchangeMessage) ckeMessage;
            BigInteger c = new BigInteger(1, rsaCke.getPublicKey().getValue());
            vulnerable = c.bitLength() <= MODULUS_LENGTH ? TestResults.TRUE : TestResults.FALSE;
        } else
            vulnerable = TestResults.FALSE;
    }

    @Override
    public void adjustConfig(ClientReport report) {
        rsaCipherSuites = new LinkedList<>();
        @SuppressWarnings("unchecked")
        List<VersionSuiteListPair> versionSuitPairs = ((ListResult<VersionSuiteListPair>) report.getResultMap()
            .get(TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS.name())).getList();
        for (VersionSuiteListPair suitePair : versionSuitPairs) {
            for (CipherSuite suite : suitePair.getCipherSuiteList()) {
                if (AlgorithmResolver.getKeyExchangeAlgorithm(suite) == KeyExchangeAlgorithm.RSA) {
                    rsaCipherSuites.add(suite);
                }
            }
        }
    }

    @Override
    protected Requirement getRequirements(ClientReport report) {
        return new ProbeRequirement(report).requireAnalyzedProperties(TlsAnalyzedProperty.SUPPORTS_RSA);
    }

    @Override
    protected void mergeData(ClientReport report) {
        super.put(TlsAnalyzedProperty.VULNERABLE_TO_FREAK, vulnerable);
    }
}
