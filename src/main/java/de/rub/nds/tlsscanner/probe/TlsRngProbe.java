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
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.header.GenericHttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
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
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS12");
            highestVersion = ProtocolVersion.TLS13;
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS11");
            highestVersion = ProtocolVersion.TLS11;
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS10");
            highestVersion = ProtocolVersion.TLS10;
        }

        // ////////////////////////////////////////////////////////////////////////////////////////////////////
        collectServerRandom(4,1);
        collectIV(100,10);
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

        List<CipherSuite> fallBackECDHCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.name().contains("TLS_ECDHE") || cipherSuite.name().contains("TLS_DHE")) {
                fallBackECDHCipherSuites.add(cipherSuite);
            }
        }

        List<NamedGroup> groups = new LinkedList<>();
        groups.addAll(Arrays.asList(NamedGroup.values()));

        testConf.setDefaultClientSupportedCiphersuites(fallBackECDHCipherSuites);
        testConf.setEnforceSettings(false);
        testConf.setAddServerNameIndicationExtension(true);
        testConf.setAddEllipticCurveExtension(true);
        testConf.setAddECPointFormatExtension(true);
        testConf.setAddSignatureAndHashAlgorithmsExtension(true);
        testConf.setAddRenegotiationInfoExtension(false);
        // tlsConfig.setWorkflowTraceType(WorkflowTraceType.CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION);
        testConf.setUseFreshRandom(false);
        testConf.setDefaultClientRandom(clientRandom);

        // Receive more if you can
        testConf.setQuickReceive(false);
        testConf.setEarlyStop(false);

        testConf.setStopActionsAfterFatal(true);
        testConf.setDefaultClientNamedGroups(groups);

        return testConf;
    }

    private void collectServerRandom(int numberOfHandshakes, int clientRandomInit){
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
        // If not one of the preferred Cipher suites is supported, use standard
        // cipher suites configured
        // in generateConfig method (i.e. ECDHE cipher suites )

        boolean supportsExtendedRandom = latestReport.getSupportedExtensions().contains(ExtensionType.EXTENDED_RANDOM);

        for (int i = 0; i < numberOfHandshakes; i++) {
            WorkflowTrace randomnessTest = new WorkflowTrace();
            Config serverHelloConfig = generateTestConfig(intToByteArray(clientRandomInit+i));
            if (supportsExtendedRandom) {
                LOGGER.warn("Extended Random Supported!");
                serverHelloConfig.setParseKeyShareOld(false);
                serverHelloConfig.setAddExtendedRandomExtension(true);
            }
            serverHelloConfig.setHighestProtocolVersion(highestVersion);
            if (!serverHelloCollectSuites.isEmpty()) {
                serverHelloConfig.setDefaultClientSupportedCiphersuites(serverHelloCollectSuites);
            }
            ClientHelloMessage client_test = new ClientHelloMessage(serverHelloConfig);
            randomnessTest.addTlsActions(new SendAction(client_test));
            randomnessTest.addTlsActions(new ReceiveAction(new ServerHelloMessage(serverHelloConfig)));
            State test_state = new State(serverHelloConfig, randomnessTest);

            LOGGER.warn("Starting test ClientHello");
            executeState(test_state);
            LOGGER.warn("===========================================================================================");
            LOGGER.warn(test_state.getWorkflowTrace());
            LOGGER.warn(test_state.getTlsContext().getSelectedProtocolVersion());
            LOGGER.warn(test_state.getTlsContext().getSelectedCipherSuite());
            LOGGER.warn("===========================================================================================");
        }
    }

    private void collectIV(int numberOfBlocks, int clientRandomInit){
        // Collect IV
        // Here it is not important which ciphersuite we use for key-exchange,
        // only important thing is maximum
        // block size of encrypted blocks.
        for (int i = 0; i < 1; i++) {
            Config iVCollectConfig = generateTestConfig(intToByteArray(clientRandomInit + i));
            iVCollectConfig.setHighestProtocolVersion(highestVersion);
            CipherSuite[] supportedSuites = new CipherSuite[latestReport.getCipherSuites().toArray().length];
            supportedSuites = latestReport.getCipherSuites().toArray(supportedSuites);
            List<CipherSuite> cbcSuites = new LinkedList<>();
            for (CipherSuite suite : supportedSuites) {
                if (suite.name().contains("CBC")) {
                    cbcSuites.add(suite);
                }
            }
            if(cbcSuites.isEmpty()){
                // No Cipher suites allow CBC Mode --> Collect more ServerRandoms instead
                // TODO: Implement Fallback to collect Server Randoms
            } else {
                iVCollectConfig.setDefaultClientSupportedCiphersuites(cbcSuites);
            }
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
    }

    private byte[] intToByteArray(int number) {
        BigInteger bigNum = BigInteger.valueOf(number);
        byte[] bigNumArray = bigNum.toByteArray();
        byte[] output = new byte[32];
        System.arraycopy(bigNumArray, 0, output, 0, bigNumArray.length);
        return output;
    }

}