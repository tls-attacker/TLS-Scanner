/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.header.GenericHttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ExtensionResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.RngResult;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class TlsRngProbe extends TlsProbe {

    private ProtocolVersion highestVersion;
    private SiteReport latestReport;

    public TlsRngProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RNG, config, 0);
    }

    @Override
    public ProbeResult executeTest() {

        // Ensure we use the highest Protocol version possible to prevent the
        // downgrade-attack mitigation to
        // activate
        if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS13");
            highestVersion = ProtocolVersion.TLS13;
            collectServerRandomTls13(4, 1);
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS12");
            highestVersion = ProtocolVersion.TLS12;
            collectServerRandom(4, 1);
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS11");
            highestVersion = ProtocolVersion.TLS11;
            collectServerRandom(4, 1);
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS10");
            highestVersion = ProtocolVersion.TLS10;
            collectServerRandom(4, 1);
        }

        // ////////////////////////////////////////////////////////////////////////////////////////////////////
        collectIV(101, 10);
        // /////////////////////////////////////////////////////////////////////////////////////////////////////

        // TODO: Implement this right.
        boolean successfulHandshake = true;

        RngResult rng_extract = new RngResult(successfulHandshake);

        return rng_extract;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_SESSION_IDS) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.HAS_EXTENSION_INTOLERANCE) == TestResult.NOT_TESTED_YET) {
            return false;
        } else {
            // We will conduct the rng extraction based on the test-results, so
            // we need those properties to be tested
            // before we conduct the RNG-Probe latestReport = report;
            this.latestReport = report;
            return true;
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new RngResult(false);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    private Config generateTestConfig(byte[] clientRandom) {
        Config testConf = getScannerConfig().createConfig();

        testConf.setEnforceSettings(false);
        testConf.setAddServerNameIndicationExtension(false);
        testConf.setAddEllipticCurveExtension(true);
        testConf.setAddECPointFormatExtension(true);
        testConf.setAddSignatureAndHashAlgorithmsExtension(true);
        testConf.setAddRenegotiationInfoExtension(false);
        testConf.setUseFreshRandom(false);
        testConf.setDefaultClientRandom(clientRandom);
        testConf.setStopActionsAfterFatal(true);

        testConf.setQuickReceive(true);
        testConf.setEarlyStop(true);

        List<NamedGroup> supportedGroups = new LinkedList<>();
        for (NamedGroup group : latestReport.getSupportedNamedGroups()) {
            if (!group.name().contains("FFDHE")) {
                supportedGroups.add(group);
            }
        }
        testConf.setDefaultClientNamedGroups(supportedGroups);

        return testConf;
    }

    private Config generateTls13Config(byte[] clientRandom) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        List<NamedGroup> tls13Groups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.values()) {
            if (group.isTls13() && !(group.name().contains("FFDHE"))) {
                tls13Groups.add(group);
            }
        }
        tlsConfig.setDefaultClientNamedGroups(tls13Groups);
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setUseFreshRandom(false);
        tlsConfig.setDefaultClientRandom(clientRandom);

        List<SignatureAndHashAlgorithm> algos = new LinkedList<>();
        algos.add(SignatureAndHashAlgorithm.RSA_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_SHA512);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);

        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(algos);
        return tlsConfig;
    }

    private void collectServerRandomTls13(int numberOfHandshakes, int clientRandomInit) {
        List<CipherSuite> serverHelloCollectSuites = new LinkedList<>();
        CipherSuite[] supportedSuites = new CipherSuite[latestReport.getSupportedTls13CipherSuites().toArray().length];
        supportedSuites = latestReport.getSupportedTls13CipherSuites().toArray(supportedSuites);
        if (latestReport.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.TRUE) {
            for (CipherSuite cipherSuite : supportedSuites) {
                if (cipherSuite.name().contains("TLS_RSA")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.TRUE) {
            for (CipherSuite cipherSuite : supportedSuites) {
                if (cipherSuite.name().contains("TLS_DH")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.TRUE) {
            for (CipherSuite cipherSuite : supportedSuites) {
                if (cipherSuite.name().contains("TLS_ECDH")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        }

        boolean supportsExtendedRandom = latestReport.getSupportedExtensions().contains(ExtensionType.EXTENDED_RANDOM);

        for (int i = 0; i < numberOfHandshakes; i++) {
            Config serverHelloConfig = generateTls13Config(intToByteArray(clientRandomInit + i));

            if (supportsExtendedRandom) {
                LOGGER.warn("Extended Random Supported!");
                serverHelloConfig.setParseKeyShareOld(false);
                serverHelloConfig.setAddExtendedRandomExtension(true);
            }

            if (!serverHelloCollectSuites.isEmpty()) {
                serverHelloConfig.setDefaultClientSupportedCiphersuites(serverHelloCollectSuites);
            } else {
                // Fallback to supported Suites
                serverHelloConfig.setDefaultClientSupportedCiphersuites(supportedSuites);
            }
            serverHelloConfig.setEnforceSettings(true);

            serverHelloConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

            State test_state = new State(serverHelloConfig);
            LOGGER.warn("Starting test ClientHello in TLS 13");
            executeState(test_state);
            LOGGER.warn("===========================================================================================");
            LOGGER.warn(test_state.getWorkflowTrace());
            LOGGER.warn(test_state.getTlsContext().getSelectedProtocolVersion());
            LOGGER.warn(test_state.getTlsContext().getSelectedCipherSuite());
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getServerSessionId()));
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getClientRandom()));
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getServerRandom()));
            LOGGER.warn("===========================================================================================");
        }

    }

    private void collectServerRandom(int numberOfHandshakes, int clientRandomInit) {
        // Use preferred Ciphersuites if supported
        List<CipherSuite> serverHelloCollectSuites = new LinkedList<>();
        CipherSuite[] supportedSuites = new CipherSuite[latestReport.getCipherSuites().toArray().length];
        supportedSuites = latestReport.getCipherSuites().toArray(supportedSuites);
        if (latestReport.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.TRUE) {
            for (CipherSuite cipherSuite : supportedSuites) {
                if (cipherSuite.name().contains("TLS_RSA")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.TRUE) {
            for (CipherSuite cipherSuite : supportedSuites) {
                if (cipherSuite.name().contains("TLS_DH")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.TRUE) {
            for (CipherSuite cipherSuite : supportedSuites) {
                if (cipherSuite.name().contains("TLS_ECDH")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        }

        boolean supportsExtendedRandom = latestReport.getSupportedExtensions().contains(ExtensionType.EXTENDED_RANDOM);

        for (int i = 0; i < numberOfHandshakes; i++) {
            Config serverHelloConfig = generateTestConfig(intToByteArray(clientRandomInit + i));

            if (supportsExtendedRandom) {
                LOGGER.warn("Extended Random Supported!");
                serverHelloConfig.setParseKeyShareOld(false);
                serverHelloConfig.setAddExtendedRandomExtension(true);
            }
            serverHelloConfig.setHighestProtocolVersion(highestVersion);
            serverHelloConfig.setSupportedVersions(highestVersion);
            if (!serverHelloCollectSuites.isEmpty()) {
                serverHelloConfig.setDefaultClientSupportedCiphersuites(serverHelloCollectSuites);
            } else {
                // Fallback to supported Suites
                serverHelloConfig.setDefaultClientSupportedCiphersuites(supportedSuites);
            }

            serverHelloConfig.setEnforceSettings(true);

            serverHelloConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

            State test_state = new State(serverHelloConfig);
            LOGGER.warn("Starting test ClientHello");
            executeState(test_state);
            LOGGER.warn("===========================================================================================");
            LOGGER.warn(test_state.getWorkflowTrace());
            LOGGER.warn(test_state.getTlsContext().getSelectedProtocolVersion());
            LOGGER.warn(test_state.getTlsContext().getSelectedCipherSuite());
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getClientRandom()));
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getServerRandom()));
            LOGGER.warn("===========================================================================================");
        }
    }

    private void collectIV(int numberOfBlocks, int clientRandomInit) {
        // Collect IV
        // Here it is not important which ciphersuite we use for key-exchange,
        // only important thing is maximum
        // block size of encrypted blocks.
        CipherSuite[] supportedSuites = new CipherSuite[latestReport.getCipherSuites().toArray().length];
        supportedSuites = latestReport.getCipherSuites().toArray(supportedSuites);
        List<CipherSuite> cbcSuites = new LinkedList<>();
        for (CipherSuite suite : supportedSuites) {
            if (suite.name().contains("CBC")) {
                // TODO: Add only the "Large" CBC suites with 16 byte block size
                cbcSuites.add(suite);
            }
        }

        if (cbcSuites.isEmpty()) {
            LOGGER.warn("NO CBC SUITES! Falling back to collect more Server Randoms instead ...");
            if (highestVersion == ProtocolVersion.TLS13) {
                collectServerRandomTls13(200, clientRandomInit + 1);
            } else {
                collectServerRandom(200, clientRandomInit + 1);
            }
            return;
        }

        // Collect IV when CBC Suites are available
        Config iVCollectConfig = generateTestConfig(intToByteArray(clientRandomInit + 1));
        iVCollectConfig.setHighestProtocolVersion(highestVersion);

        iVCollectConfig.setDefaultClientSupportedCiphersuites(cbcSuites);
        ProtocolMessage[] flight1 = { new ChangeCipherSpecMessage(iVCollectConfig),
                new FinishedMessage(iVCollectConfig) };
        List<ProtocolMessage> serverHello = new ArrayList<>();
        serverHello.add(new ServerHelloMessage(iVCollectConfig));
        serverHello.add(new CertificateMessage(iVCollectConfig));
        if (latestReport.getResult(AnalyzedProperty.SUPPORTS_ECDH) == TestResult.TRUE) {
            serverHello.add(new ECDHEServerKeyExchangeMessage(iVCollectConfig));
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.TRUE) {
            serverHello.add(new DHEServerKeyExchangeMessage(iVCollectConfig));
        }
        serverHello.add(new ServerHelloDoneMessage(iVCollectConfig));
        ProtocolMessage[] serverHelloFlight = new ProtocolMessage[serverHello.size()];
        serverHelloFlight = serverHello.toArray(serverHelloFlight);
        WorkflowTrace ivCollectorTrace = new WorkflowTrace();
        ivCollectorTrace.addTlsAction(new SendAction(new ClientHelloMessage(iVCollectConfig)));
        ivCollectorTrace.addTlsAction(new ReceiveAction(serverHelloFlight));
        ivCollectorTrace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        ivCollectorTrace.addTlsAction(new SendAction(flight1));
        ivCollectorTrace.addTlsAction(new ReceiveAction(flight1));
        for (int j = 0; j < numberOfBlocks; j++) {
            HttpsRequestMessage request = new HttpsRequestMessage();
            List<HttpsHeader> header = new LinkedList<>();
            header.add(new HostHeader());
            // header.add(new GenericHttpsHeader("Connection",
            // "keep-alive"));
            request.setHeader(header);
            ivCollectorTrace.addTlsAction(new SendAction(request));
            ivCollectorTrace.addTlsAction(new ReceiveAction(new ApplicationMessage()));
        }
        State state = new State(iVCollectConfig, ivCollectorTrace);
        executeState(state);
        LOGGER.warn(state.getWorkflowTrace());
        LOGGER.warn(state.getTlsContext().getSelectedProtocolVersion());
        LOGGER.warn(state.getTlsContext().getSelectedCipherSuite());
    }

    private byte[] intToByteArray(int number) {
        BigInteger bigNum = BigInteger.valueOf(number);
        byte[] bigNumArray = bigNum.toByteArray();
        byte[] output = new byte[32];
        System.arraycopy(bigNumArray, 0, output, 0, bigNumArray.length);
        return output;
    }

}