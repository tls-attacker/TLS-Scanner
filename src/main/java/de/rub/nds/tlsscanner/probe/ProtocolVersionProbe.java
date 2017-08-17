/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProtocolVersionProbe extends TLSProbe {

    public ProtocolVersionProbe(ScannerConfig config) {
        super(ProbeType.PROTOCOL_VERSION, config);
    }

    @Override
    public ProbeResult call() {
        List<ResultValue> resultList = new LinkedList<>();
        List<TLSCheck> checkList = new LinkedList<>();
        LOGGER.debug("Testing SSL2:");
        boolean result = isSSL2Supported();
        resultList.add(new ResultValue("SSL 2", "" + result));
        checkList.add(new TLSCheck(result, CheckType.PROTOCOLVERSION_SSL2, 10));
        LOGGER.debug("Testing SSL3:");
        result = isProtocolVersionSupported(ProtocolVersion.SSL3);
        resultList.add(new ResultValue("SSL 3", "" + result));
        checkList.add(new TLSCheck(result, CheckType.PROTOCOLVERSION_SSL3, 10));
        LOGGER.debug("Testing TLS 1.0:");
        result = isProtocolVersionSupported(ProtocolVersion.TLS10);
        resultList.add(new ResultValue("TLS 1.0", "" + result));
        LOGGER.debug("Testing TLS 1.1:");
        result = isProtocolVersionSupported(ProtocolVersion.TLS11);
        resultList.add(new ResultValue("TLS 1.1", "" + result));
        LOGGER.debug("Testing TLS 1.2:");
        result = isProtocolVersionSupported(ProtocolVersion.TLS12);
        resultList.add(new ResultValue("TLS 1.2", "" + result));
        return new ProbeResult(getType(), resultList, checkList);

    }

    public boolean isProtocolVersionSupported(ProtocolVersion toTest) {
        Config tlsConfig = getConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(toTest);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopRecievingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        if (toTest != ProtocolVersion.SSL2) {
            tlsConfig.setAddServerNameIndicationExtension(false);
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(true);
        } else {
            // Dont send extensions if we are in sslv2
            tlsConfig.setAddECPointFormatExtension(false);
            tlsConfig.setAddEllipticCurveExtension(false);
            tlsConfig.setAddHeartbeatExtension(false);
            tlsConfig.setAddMaxFragmentLengthExtenstion(false);
            tlsConfig.setAddServerNameIndicationExtension(false);
            tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(false);
        }
        List<NamedCurve> namedCurves = Arrays.asList(NamedCurve.values());

        tlsConfig.setNamedCurves(namedCurves);
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT,
                tlsContext);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
        }
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(tlsContext.getWorkflowTrace().toString());
            return false;
        } else {    
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug(tlsContext.getWorkflowTrace().toString());
            LOGGER.debug("Selected Version:" + tlsContext.getSelectedProtocolVersion().name());
            return tlsContext.getSelectedProtocolVersion() == toTest;
        }
    }

    private boolean isSSL2Supported() {
        Config tlsConfig = getConfig().createConfig();
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.SSL2);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setRecordLayerType(RecordLayerType.BLOB);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new SSL2ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveAction(new SSL2ServerHelloMessage()));
        tlsConfig.setWorkflowTrace(trace);
        TlsContext context = new TlsContext(tlsConfig);
        context.setClientSessionId(new byte[0]);
        WorkflowExecutor executor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, context);
        executor.executeWorkflow();
        return trace.executedAsPlanned();
    }

}
