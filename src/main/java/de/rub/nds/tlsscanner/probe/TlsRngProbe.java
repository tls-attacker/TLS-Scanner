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
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.https.header.GenericHttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.RngResult;
import de.rub.nds.tlsscanner.report.result.Tls13Result;
import sun.net.www.http.HttpClient;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsRngProbe extends TlsProbe {

    public TlsRngProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RNG, config, 0);
    }

    @Override
    public ProbeResult executeTest() {

        Config tlsConfig = getScannerConfig().createConfig();

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
        // tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);

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

        byte[] conf = { (byte) 01, (byte) 42 };

        alert.setConfig(conf);

        HttpsRequestMessage request = new HttpsRequestMessage(tlsConfig);

        // WorkflowConfigurationFactory factory = new
        // WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = new WorkflowTrace();

        ProtocolMessage[] flight1 = { new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig) };
        ProtocolMessage[] hello = { new ServerHelloMessage(tlsConfig), new CertificateMessage(tlsConfig),
                new ECDHEServerKeyExchangeMessage(tlsConfig), new ServerHelloDoneMessage(tlsConfig) };

        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveAction(hello));
        trace.addTlsAction(new SendAction(new ECDHClientKeyExchangeMessage(tlsConfig)));
        trace.addTlsAction(new SendAction(flight1));
        trace.addTlsAction(new ReceiveAction(flight1));

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

        State state = new State(tlsConfig, trace);
        executeState(state);
        boolean successfulHandshake = state.getWorkflowTrace().executedAsPlanned();

        RngResult rng_extract = new RngResult(successfulHandshake);

        LOGGER.warn(state.getWorkflowTrace());

        LOGGER.warn(state.getTlsContext().getLastRecordVersion());
        LOGGER.warn(state.getTlsContext().getSelectedCipherSuite());

        // List<AbstractRecord> allReceivedMessages =
        // WorkflowTraceUtil.getAllReceivedRecords(trace);

        return rng_extract;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new RngResult(false);
    }

    @Override
    public void adjustConfig(SiteReport report) {

    }
}
