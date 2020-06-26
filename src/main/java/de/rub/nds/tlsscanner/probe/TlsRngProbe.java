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
         if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) ==
         TestResult.TRUE)
            { highestVersion = ProtocolVersion.TLS13; }
         else if
         (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) ==
         TestResult.TRUE)
            { highestVersion = ProtocolVersion.TLS13; }
         else if
         (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) ==
         TestResult.TRUE)
            { highestVersion = ProtocolVersion.TLS11; }
         else if
         (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) ==
         TestResult.TRUE)
            { highestVersion = ProtocolVersion.TLS10; }

        //////////////////////////////////////////////////////////////////////////////////////////////////////

        // Use preferred Ciphersuites if supported
        List<CipherSuite> serverHelloCollectSuites = new LinkedList<>();
        if(latestReport.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.TRUE){
            for (CipherSuite cipherSuite : CipherSuite.values()) {
                if (cipherSuite.name().contains("TLS_RSA")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.TRUE){
            for(CipherSuite cipherSuite : CipherSuite.values()){
                if(cipherSuite.name().contains("TLS_DH")){
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.TRUE){
            for(CipherSuite cipherSuite : CipherSuite.values()){
                if(cipherSuite.name().contains("TLS_ECDH")){
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        }
        // If not one of the preferred Cipher suites is supported, use standard cipher suites configured
        // in generateConfig method (i.e. ECDHE cipher suites )

        for (int i = 0; i < 4; i++) {
            WorkflowTrace randomnessTest = new WorkflowTrace();
            Config serverHelloConfig = generateTestConfig(intToByteArray(i + 1));
            serverHelloConfig.setAddExtendedRandomExtension(true);
            serverHelloConfig.setHighestProtocolVersion(highestVersion);
            serverHelloConfig.setDefaultClientSupportedCiphersuites(serverHelloCollectSuites);

            ClientHelloMessage client_test = new ClientHelloMessage(serverHelloConfig);
            randomnessTest.addTlsActions(new SendAction(client_test));
            randomnessTest.addTlsActions(new ReceiveAction(new ServerHelloMessage(serverHelloConfig)));

            State test_state = new State(serverHelloConfig, randomnessTest);
            LOGGER.warn("Starting test ClientHello");
            executeState(test_state);
            LOGGER.warn(test_state.getWorkflowTrace());
        }

        // /////////////////////////////////////////////////////////////////////////////////////////////////////

        // Collect IV
        // Here it is not important which ciphersuite we use for key-exchange, only important thing is maximum
        // block size of encrypted blocks.
        Config iVCollectConfig = generateTestConfig(intToByteArray(600));
        iVCollectConfig.setHighestProtocolVersion(highestVersion);

        ProtocolMessage[] flight1 = { new ChangeCipherSpecMessage(iVCollectConfig),
                new FinishedMessage(iVCollectConfig) };
        List<ProtocolMessage> serverHello = new ArrayList<>();
        serverHello.add(new ServerHelloMessage(iVCollectConfig));
        serverHello.add(new CertificateMessage(iVCollectConfig));

        if(latestReport.getResult(AnalyzedProperty.SUPPORTS_ECDH) == TestResult.TRUE){
            serverHello.add(new ECDHEServerKeyExchangeMessage(iVCollectConfig));
        } else if(latestReport.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.TRUE){
            serverHello.add(new DHEServerKeyExchangeMessage(iVCollectConfig));
        }

        serverHello.add(new ServerHelloDoneMessage(iVCollectConfig));

        WorkflowTrace ivCollectorTrace = new WorkflowTrace();
        ivCollectorTrace.addTlsAction(new SendAction(new ClientHelloMessage(iVCollectConfig)));
        ivCollectorTrace.addTlsAction(new ReceiveAction((ProtocolMessage[]) serverHello.toArray()));
        ivCollectorTrace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        ivCollectorTrace.addTlsAction(new SendAction(flight1));
        ivCollectorTrace.addTlsAction(new ReceiveAction(flight1));

        // HTTP Request
        // HttpsRequestMessage request = new HttpsRequestMessage(tlsConfig);
        HttpsRequestMessage request = new HttpsRequestMessage();
        List<HttpsHeader> header = new LinkedList<>();
        header.add(new HostHeader());
        // header.add(new GenericHttpsHeader("Connection", "keep-alive"));
        request.setHeader(header);

        for(int i=0; i<32; i++){
            ivCollectorTrace.addTlsAction(new SendAction(request));
            ivCollectorTrace.addTlsAction(new ReceiveAction(new ApplicationMessage()));
        }
        State state = new State(iVCollectConfig, ivCollectorTrace);
        executeState(state);
        LOGGER.warn(state.getWorkflowTrace());

        boolean successfulHandshake = state.getWorkflowTrace().executedAsPlanned();

        RngResult rng_extract = new RngResult(successfulHandshake);

        return rng_extract;
    }

    @Override
     public boolean canBeExecuted(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_CBC) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_SESSION_IDS) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.NOT_TESTED_YET) {
            return false;
        }
        else {
            // We will conduct the rng extraction based on the test-results, so
            // we need those properties to be tested
            // before we conduct the RNG-Probe latestReport = report;
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
        testConf.setAddExtendedMasterSecretExtension(false);

        // Receive more if you can
        testConf.setQuickReceive(false);
        testConf.setEarlyStop(false);

        testConf.setStopActionsAfterFatal(true);
        testConf.setDefaultClientNamedGroups(groups);

        return testConf;
    }

    private byte[] intToByteArray(int number) {
        BigInteger bigNum = BigInteger.valueOf(number);
        byte[] bigNumArray = bigNum.toByteArray();
        byte[] output = new byte[32];
        System.arraycopy(bigNumArray, 0, output, 0, bigNumArray.length);
        return output;
    }

}