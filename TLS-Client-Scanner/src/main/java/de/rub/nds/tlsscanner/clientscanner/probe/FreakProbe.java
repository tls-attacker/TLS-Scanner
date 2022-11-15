/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

<<<<<<< HEAD
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResult;
=======
>>>>>>> master
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeServerRsaParametersAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
<<<<<<< HEAD
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyRequirement;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
=======
>>>>>>> master
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

<<<<<<< HEAD
// see https://www.smacktls.com/smack.pdf section V-D
public class FreakProbe extends TlsClientProbe<ClientScannerConfig, ClientReport> {
=======
// See https://www.ieee-security.org/TC/SP2015/papers-archived/6949a535.pdf section V-D.
public class FreakProbe extends TlsClientProbe<ClientScannerConfig, ClientReport, FreakResult> {
>>>>>>> master

    private static final int FREAK_N_BITLENGTH = 512;
    private static final String FREAK_MODULUS =
            "959183137234245978190806322236721051559442279211426254570156522"
                    + "9434010745323400851802978361800682386367519783577333645693004555704072018682703042687779049";
    private static final String FREAK_PUBLIC_KEY = "65537";
    private static final String FREAK_PRIVATE_KEY =
            "90628953731413115808641377987799987298343446077191735907575571"
                    + "61637582546998623882628794294395441240308041795327669106449640328485739194560936631604548017";

<<<<<<< HEAD
    private static final int P_LEN = 256;
    private static final int Q_LEN = 256;
    private static final int MODULUS_LENGTH = P_LEN + Q_LEN;

    private List<CipherSuite> rsaCipherSuites;
    private TestResult vulnerable;

    private Random random = new Random(0); // Fixed random to be deterministic
=======
    private List<CipherSuite> supportedRsaCipherSuites;
>>>>>>> master

    public FreakProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.FREAK, scannerConfig);
        register(TlsAnalyzedProperty.VULNERABLE_TO_FREAK);
    }

    @Override
<<<<<<< HEAD
    public void executeTest() {
        Config config = scannerConfig.createConfig();
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS12);
        config.setSupportedVersions(ProtocolVersion.SSL3, ProtocolVersion.TLS10, ProtocolVersion.TLS11,
            ProtocolVersion.TLS12);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
        // Set value in config for workflow trace generation - we will set it later back
        config.setDefaultServerSupportedCipherSuites(rsaCipherSuites);
=======
    public FreakResult executeTest() {
        BigInteger modulus = new BigInteger(FREAK_MODULUS);
        BigInteger publicKey = new BigInteger(FREAK_PUBLIC_KEY);
        BigInteger privateKey = new BigInteger(FREAK_PRIVATE_KEY);
>>>>>>> master

        Config config = scannerConfig.createConfig();
        config.setDefaultServerSupportedCipherSuites(supportedRsaCipherSuites);
        config.setDefaultServerRSAModulus(modulus);
        config.setDefaultServerRSAPublicKey(publicKey);
        config.setDefaultServerRSAPrivateKey(privateKey);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.SHORT_HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new SendAction(new CertificateMessage(config)));
        trace.addTlsAction(new ChangeServerRsaParametersAction(modulus, publicKey, privateKey));
        trace.addTlsAction(
                new SendAction(
                        new RSAServerKeyExchangeMessage(config),
                        new ServerHelloDoneMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        executeState(new State(config, trace));

        HandshakeMessage ckeMessage =
                WorkflowTraceUtil.getFirstReceivedMessage(
                        HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
        if (ckeMessage != null && ckeMessage instanceof RSAClientKeyExchangeMessage) {
<<<<<<< HEAD
            RSAClientKeyExchangeMessage rsaCke = (RSAClientKeyExchangeMessage) ckeMessage;
            BigInteger c = new BigInteger(1, rsaCke.getPublicKey().getValue());
            vulnerable = c.bitLength() <= MODULUS_LENGTH ? TestResults.TRUE : TestResults.FALSE;
        } else
            vulnerable = TestResults.FALSE;
=======
            RSAClientKeyExchangeMessage rsaCkeMessage = (RSAClientKeyExchangeMessage) ckeMessage;
            BigInteger encryptedPMS = new BigInteger(1, rsaCkeMessage.getPublicKey().getValue());
            int encryptedPMSBitLength = encryptedPMS.bitLength();
            LOGGER.debug(
                    "FREAK probe encrypted premaster secret is {} bits", encryptedPMSBitLength);
            if (encryptedPMSBitLength <= FREAK_N_BITLENGTH) {
                return new FreakResult(TestResults.TRUE);
            }
        }
        return new FreakResult(TestResults.FALSE);
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.CIPHER_SUITE)
                && report.getResult(TlsAnalyzedProperty.SUPPORTS_RSA) == TestResults.TRUE;
    }

    @Override
    public FreakResult getCouldNotExecuteResult() {
        return new FreakResult(TestResults.COULD_NOT_TEST);
>>>>>>> master
    }

    @Override
    public void adjustConfig(ClientReport report) {
        supportedRsaCipherSuites = new LinkedList<>();
        for (CipherSuite suite : report.getCipherSuites()) {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite) == KeyExchangeAlgorithm.RSA) {
                supportedRsaCipherSuites.add(suite);
            }
        }
    }

    @Override
    protected Requirement getRequirements() {
        return new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_RSA);
    }

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.VULNERABLE_TO_FREAK, vulnerable);
    }
}
