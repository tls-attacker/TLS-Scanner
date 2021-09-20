/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.Modifiable;
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
import de.rub.nds.tlsattacker.core.workflow.action.ChangeRsaParametersAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.probe.result.FreakResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import java.util.LinkedList;

// see https://www.smacktls.com/smack.pdf section V-D
public class FreakProbe extends TlsProbe<ClientReport, FreakResult> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int P_LEN = 256;
    private static final int Q_LEN = 256;
    private static final int MODULUS_LENGTH = P_LEN + Q_LEN;

    private List<CipherSuite> rsaCipherSuites;

    private Random random = new Random(0); // Fixed random to be deterministic

    public FreakProbe(ParallelExecutor executor, ScannerConfig scannerConfig) {
        super(executor, TlsProbeType.FREAK, scannerConfig);
    }

    @Override
    public FreakResult executeTest() {
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
        TlsAction fixKeysAction = new ChangeRsaParametersAction(modulus, publicExponent, privateKey);
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
            if (c.bitLength() <= MODULUS_LENGTH) {
                return new FreakResult(TestResult.TRUE);
            } else {
                return new FreakResult(TestResult.FALSE);
            }
        } else {
            return new FreakResult(TestResult.FALSE);
        }
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return report.getResult(TlsAnalyzedProperty.SUPPORTS_RSA) == TestResult.TRUE;
    }

    @Override
    public FreakResult getCouldNotExecuteResult() {
        return new FreakResult(TestResult.CANNOT_BE_TESTED);
    }

    @Override
    public void adjustConfig(ClientReport report) {
        rsaCipherSuites = new LinkedList<>();
        List<VersionSuiteListPair> versionSuitPairs = report.getVersionSuitPairs();
        for (VersionSuiteListPair suitePair : versionSuitPairs) {
            for (CipherSuite suite : suitePair.getCipherSuiteList()) {
                if (AlgorithmResolver.getKeyExchangeAlgorithm(suite) == KeyExchangeAlgorithm.RSA) {
                    rsaCipherSuites.add(suite);
                }
            }
        }
    }
}
