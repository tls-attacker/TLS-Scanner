/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.report.result.CiphersuiteProbeResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TlsCheck;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CiphersuiteProbe extends TlsProbe {

    private final List<ProtocolVersion> protocolVersions;

    public CiphersuiteProbe(ScannerConfig config) {
        super(ProbeType.CIPHERSUITE, config,0);
        protocolVersions = new LinkedList<>();
        protocolVersions.add(ProtocolVersion.TLS10);
        protocolVersions.add(ProtocolVersion.TLS11);
        protocolVersions.add(ProtocolVersion.TLS12);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting CiphersuiteProbe");
        List<VersionSuiteListPair> pairLists = new LinkedList<>();
        for (ProtocolVersion version : protocolVersions) {
            LOGGER.debug("Testing:" + version.name());
            List<CipherSuite> toTestList = new LinkedList<>();
            toTestList.addAll(Arrays.asList(CipherSuite.values()));
            toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
            List<CipherSuite> versionSupportedSuites = getSupportedCipherSuitesFromList(toTestList, version);
            pairLists.add(new VersionSuiteListPair(version, versionSupportedSuites));
        }
        
        return new CiphersuiteProbeResult(pairLists);

    }

    public List<CipherSuite> getSupportedCipherSuitesFromList(List<CipherSuite> toTestList, ProtocolVersion version) {
        List<CipherSuite> listWeSupport = new LinkedList<>(toTestList);
        List<CipherSuite> supported = new LinkedList<>();

        boolean supportsMore = false;
        do {
            Config config = getScannerConfig().createConfig();
            config.setDefaultClientSupportedCiphersuites(listWeSupport);
            config.setHighestProtocolVersion(version);
            config.setEnforceSettings(true);
            config.setAddServerNameIndicationExtension(false);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(true);
            config.setAddSignatureAndHashAlgrorithmsExtension(true);
            config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
            config.setQuickReceive(true);
            config.setEarlyStop(true);
            config.setStopActionsAfterFatal(true);
            List<NamedCurve> namedCurves = new LinkedList<>();
            namedCurves.addAll(Arrays.asList(NamedCurve.values()));
            config.setNamedCurves(namedCurves);
            State state = new State(config);
            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state);
            try {
                workflowExecutor.executeWorkflow();
            } catch (WorkflowExecutionException ex) {
                LOGGER.warn("Encountered exception while executing WorkflowTrace!");
                LOGGER.debug(ex);
                supportsMore = false;
            }
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
                if (state.getTlsContext().getSelectedProtocolVersion() != version) {
                    LOGGER.debug("Server does not support " + version);
                    return new LinkedList<>();
                }
                LOGGER.debug("Server chose " + state.getTlsContext().getSelectedCipherSuite().name());
                supportsMore = true;
                supported.add(state.getTlsContext().getSelectedCipherSuite());
                listWeSupport.remove(state.getTlsContext().getSelectedCipherSuite());
            } else {
                supportsMore = false;
                LOGGER.debug("Server did not send ServerHello");
                LOGGER.debug(state.getWorkflowTrace().toString());
                if (state.getTlsContext().isReceivedFatalAlert()) {
                    LOGGER.debug("Received Fatal Alert");
                    AlertMessage alert = (AlertMessage) WorkflowTraceUtil.getFirstReceivedMessage(ProtocolMessageType.ALERT, state.getWorkflowTrace());
                    LOGGER.debug("Type:" + alert.toString());

                }
            }
        } while (supportsMore);
        return supported;
    }

}
