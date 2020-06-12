/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.https.header.GenericHttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.Keylogfile;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
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
import de.rub.nds.tlsscanner.report.result.Tls13Result;
import sun.net.www.http.HttpClient;
import sun.net.www.http.KeepAliveCache;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsRngProbe extends TlsProbe {

    private ProtocolVersion highestVersion;
    private SiteReport latestReport;

    public TlsRngProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RNG, config, 0);
    }

    @Override
    public ProbeResult executeTest() {

        // Ensure we use the highest Protocol version possible to prevent the downgrade-attack mitigation to
        // activate
        if(latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE){
            highestVersion = ProtocolVersion.TLS13;
        } else if(latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.TRUE){
            highestVersion = ProtocolVersion.TLS13;
        } else if(latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.TRUE){
            highestVersion = ProtocolVersion.TLS11;
        } else if(latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.TRUE){
            highestVersion = ProtocolVersion.TLS10;
        }

        Config tlsConfig = getScannerConfig().createConfig();

        // TODO: Select supported Ciphersuites dynamically to force the random-bytes to an order
        List<CipherSuite> ourECDHCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.name().contains("TLS_ECDH")) {
                ourECDHCipherSuites.add(cipherSuite);
            }
        }

        List<NamedGroup> groups = new LinkedList<>();
        groups.addAll(Arrays.asList(NamedGroup.values()));

        tlsConfig.setDefaultClientSupportedCiphersuites(ourECDHCipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setWriteKeylogFile(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        // tlsConfig.setWorkflowTraceType(WorkflowTraceType.CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION);

        // Heartbeat
        tlsConfig.setAddHeartbeatExtension(true);
        tlsConfig.setHeartbeatMode(HeartbeatMode.PEER_ALLOWED_TO_SEND);

        // Receive more if you can
        tlsConfig.setQuickReceive(false);
        tlsConfig.setEarlyStop(false);

        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setDefaultClientNamedGroups(groups);

        // State state = new State(tlsConfig);
        AlertMessage alert = new AlertMessage();
        byte[] conf = { (byte) 01, (byte) 51 };

        alert.setConfig(conf);

        // HTTP Request
        // HttpsRequestMessage request = new HttpsRequestMessage(tlsConfig);
        HttpsRequestMessage request = new HttpsRequestMessage();
        List<HttpsHeader> header = new LinkedList<>();
        header.add(new HostHeader());
        // header.add(new GenericHttpsHeader("Connection", "keep-alive"));
        request.setHeader(header);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace serverHelloTrace = new WorkflowTrace();

        ProtocolMessage[] flight1 = { new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig) };
        ProtocolMessage[] hello = { new ServerHelloMessage(tlsConfig), new CertificateMessage(tlsConfig),
                new ECDHEServerKeyExchangeMessage(tlsConfig), new ServerHelloDoneMessage(tlsConfig) };

        // COLLECT SERVER RANDOMS (1KB) & SESSION-IDs (Best Case 1KB)
        AliasedConnection connection = tlsConfig.getDefaultClientConnection();

        serverHelloTrace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT,
                new ClientHelloMessage(tlsConfig)));
        serverHelloTrace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.SERVER,
                new ServerHelloMessage(tlsConfig)));

        // trace.addTlsAction(new SendAction(new
        // ClientHelloMessage(tlsConfig)));
        // trace.addTlsAction(new ReceiveAction(hello));
        // trace.addTlsAction(new SendAction(new
        // ECDHClientKeyExchangeMessage(tlsConfig)));
        // trace.addTlsAction(new SendAction(flight1));
        // trace.addTlsAction(new ReceiveAction(flight1));

        // HeartbeatMessage heartbeatTest = new HeartbeatMessage(tlsConfig);
        // heartbeatTest.setHeartbeatMessageType((byte) 1);

        // trace.addTlsAction(new SendAction(heartbeatTest));
        // trace.addTlsAction(new ReceiveAction());

        // If Renegotiaton is enabled/supported by the server

        // trace.addTlsAction(new SendAction(new
        // ClientHelloMessage(tlsConfig)));
        // trace.addTlsAction(new ReceiveAction(hello));

        // Sending Application Data --> HTTP GET

        // trace.addTlsAction(new SendAction(request));
        // trace.addTlsAction(new ReceiveAction(new ApplicationMessage()));

        // Sending TLS-Alert (Detailled Definition above)

        // trace.addTlsAction(new SendAction(alert));
        // trace.addTlsAction(new ReceiveAction());

        // State state = new State(tlsConfig, trace);

        // Collect ServerHellos & ServerIDs

        serverHelloTrace.addTlsActions();

        State state = new State(tlsConfig, serverHelloTrace);
        executeState(state);
        LOGGER.warn(state.getWorkflowTrace());
        executeState(state);
        LOGGER.warn(state.getWorkflowTrace());
        executeState(state);
        LOGGER.warn(state.getWorkflowTrace());
        executeState(state);
        LOGGER.warn(state.getWorkflowTrace());

        // Collect IV
        WorkflowTrace ivCollectorTrace = new WorkflowTrace();
        ivCollectorTrace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        ivCollectorTrace.addTlsAction(new ReceiveAction(hello));
        ivCollectorTrace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        ivCollectorTrace.addTlsAction(new SendAction(flight1));
        ivCollectorTrace.addTlsAction(new ReceiveAction(flight1));

        for (int i = 0; i < 32; i++) {
            ivCollectorTrace.addTlsAction(new SendAction(request));
            ivCollectorTrace.addTlsAction(new ReceiveAction(new ApplicationMessage()));
        }

        state = new State(tlsConfig, ivCollectorTrace);
        executeState(state);
        LOGGER.warn(state.getWorkflowTrace());

        boolean successfulHandshake = state.getWorkflowTrace().executedAsPlanned();

        RngResult rng_extract = new RngResult(successfulHandshake);

        LOGGER.warn(state.getTlsContext().getLastRecordVersion());
        LOGGER.warn(state.getTlsContext().getSelectedCipherSuite());

        // List<AbstractRecord> allReceivedMessages =
        // WorkflowTraceUtil.getAllReceivedRecords(trace);

        return rng_extract;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if(report.getResult(AnalyzedProperty.SUPPORTS_CBC) == TestResult.NOT_TESTED_YET || report.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.NOT_TESTED_YET || report.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.NOT_TESTED_YET || report.getResult(AnalyzedProperty.SUPPORTS_SESSION_IDS) == TestResult.NOT_TESTED_YET || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.NOT_TESTED_YET || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.NOT_TESTED_YET || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.NOT_TESTED_YET || report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.NOT_TESTED_YET){
            return false;
        } else{
            // We will conduct the rng extraction based on the test-results, so we need those properties to be tested
            // before we conduct the RNG-Probe
            latestReport = report;
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
}
