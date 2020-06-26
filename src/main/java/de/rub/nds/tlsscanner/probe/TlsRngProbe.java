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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.lang.reflect.Field;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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

        List<NamedGroup> groups = new LinkedList<>();
        groups.addAll(Arrays.asList(NamedGroup.values()));

        // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

        for (int i = 0; i < 4; i++) {
            WorkflowTrace randomnessTest = new WorkflowTrace();
            Config serverHelloConfig = generateTestConfig(intToByteArray(i + 1));
            serverHelloConfig.setAddExtendedRandomExtension(true);
            serverHelloConfig.setHighestProtocolVersion(highestVersion);

            ClientHelloMessage client_test = new ClientHelloMessage(serverHelloConfig);
            randomnessTest.addTlsActions(new SendAction(client_test));
            randomnessTest.addTlsActions(new ReceiveAction());

            State test_state = new State(serverHelloConfig, randomnessTest);
            LOGGER.warn("Starting test ClientHello");
            executeState(test_state);
            LOGGER.warn(test_state.getWorkflowTrace());
        }

        // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

        // Collect IV
        Config iVCollectConfig = generateTestConfig(intToByteArray(600));
        iVCollectConfig.setHighestProtocolVersion(highestVersion);

        ProtocolMessage[] flight1 = { new ChangeCipherSpecMessage(iVCollectConfig), new FinishedMessage(iVCollectConfig) };
        List<ProtocolMessage> hello = new ArrayList<>();
        hello.add(new ServerHelloMessage(iVCollectConfig));
        hello.add(new CertificateMessage(iVCollectConfig));
        // TODO: Add dynamic receiving action
        //hello.add();
        hello.add(new ServerHelloDoneMessage(iVCollectConfig));

        WorkflowTrace ivCollectorTrace = new WorkflowTrace();
        ivCollectorTrace.addTlsAction(new SendAction(new ClientHelloMessage(iVCollectConfig)));
        ivCollectorTrace.addTlsAction(new ReceiveAction((ProtocolMessage[]) hello.toArray()));
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

        // TODO:
        boolean successfulHandshake = true;

        RngResult rng_extract = new RngResult(successfulHandshake);

        // List<AbstractRecord> allReceivedMessages =
        // WorkflowTraceUtil.getAllReceivedRecords(trace);

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

        // TODO: Select supported Ciphersuites dynamically to force the
        // random-bytes to an order
        // TODO: I.e. prefer ciphersuites without key exchange messages from server
        List<CipherSuite> ourECDHCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.name().contains("TLS_ECDH")) {
                ourECDHCipherSuites.add(cipherSuite);
            }
        }

        List<NamedGroup> groups = new LinkedList<>();
        groups.addAll(Arrays.asList(NamedGroup.values()));

        testConf.setDefaultClientSupportedCiphersuites(ourECDHCipherSuites);
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