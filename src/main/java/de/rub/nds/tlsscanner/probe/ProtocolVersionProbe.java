/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.ProtocolVersionResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProtocolVersionProbe extends TlsProbe {

    private List<ProtocolVersion> toTestList;

    public ProtocolVersionProbe(ScannerConfig config) {
        super(ProbeType.PROTOCOL_VERSION, config, 0);
        toTestList = new LinkedList<>();
        toTestList.add(ProtocolVersion.SSL2);
        toTestList.add(ProtocolVersion.SSL3);
        toTestList.add(ProtocolVersion.TLS10);
        toTestList.add(ProtocolVersion.TLS11);
        toTestList.add(ProtocolVersion.TLS12);
        toTestList.add(ProtocolVersion.TLS13);
        toTestList.add(ProtocolVersion.TLS13_DRAFT14);
        toTestList.add(ProtocolVersion.TLS13_DRAFT15);
        toTestList.add(ProtocolVersion.TLS13_DRAFT16);
        toTestList.add(ProtocolVersion.TLS13_DRAFT17);
        toTestList.add(ProtocolVersion.TLS13_DRAFT18);
        toTestList.add(ProtocolVersion.TLS13_DRAFT19);
        toTestList.add(ProtocolVersion.TLS13_DRAFT20);
        toTestList.add(ProtocolVersion.TLS13_DRAFT21);
        toTestList.add(ProtocolVersion.TLS13_DRAFT22);
    }

    @Override
    public ProbeResult executeTest() {
        List<ProtocolVersion> supportedVersionList = new LinkedList<>();
        List<ProtocolVersion> unsupportedVersionList = new LinkedList<>();
        for (ProtocolVersion version : toTestList) {
            if (isProtocolVersionSupported(version)) {

                supportedVersionList.add(version);
            } else {
                unsupportedVersionList.add(version);
            }
        }
        return new ProtocolVersionResult(supportedVersionList, unsupportedVersionList);
    }

    public boolean isProtocolVersionSupported(ProtocolVersion toTest) {
        if (toTest == ProtocolVersion.SSL2) {
            return isSSL2Supported();
        }
        if (toTest.isTLS13()) {
            return isTls13Supported(toTest);
        }
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        tlsConfig.setDefaultSelectedProtocolVersion(toTest);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(toTest);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopRecievingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        if (toTest == ProtocolVersion.SSL2) {
            // Dont send extensions if we are in sslv2
            tlsConfig.setAddECPointFormatExtension(false);
            tlsConfig.setAddEllipticCurveExtension(false);
            tlsConfig.setAddHeartbeatExtension(false);
            tlsConfig.setAddMaxFragmentLengthExtenstion(false);
            tlsConfig.setAddServerNameIndicationExtension(false);
            tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(false);
        } else {
            tlsConfig.setAddServerNameIndicationExtension(true);
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(false);
        }
        List<NamedCurve> namedCurves = Arrays.asList(NamedCurve.values());

        tlsConfig.setNamedCurves(namedCurves);
        State state = new State(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT,
                state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.debug(ex);
        }
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return false;
        } else {
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug(state.getWorkflowTrace().toString());
            LOGGER.debug("Selected Version:" + state.getTlsContext().getSelectedProtocolVersion().name());
            return state.getTlsContext().getSelectedProtocolVersion() == toTest;
        }
    }

    private boolean isSSL2Supported() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.SSL2);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setRecordLayerType(RecordLayerType.BLOB);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new SSL2ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveAction(new SSL2ServerHelloMessage(tlsConfig)));
        State state = new State(tlsConfig, trace);
        WorkflowExecutor executor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state);
        executor.executeWorkflow();
        return trace.executedAsPlanned();
    }

    private boolean isTls13Supported(ProtocolVersion toTest) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(getTls13Suite());
        tlsConfig.setHighestProtocolVersion(toTest);
        tlsConfig.setSupportedVersions(toTest);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopRecievingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        tlsConfig.setNamedCurves(NamedCurve.ECDH_X25519, NamedCurve.SECP256R1, NamedCurve.SECP384R1, NamedCurve.SECP521R1, NamedCurve.ECDH_X448);
        //TODO add support for named groups
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setUseRandomUnixTime(true);
        tlsConfig.setSupportedSignatureAndHashAlgorithms(getTls13SignatureAndHashAlgorithms());
        State state = new State(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT,
                state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.debug(ex);
        }
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return false;
        } else {
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug(state.getWorkflowTrace().toString());
            LOGGER.debug("Selected Version:" + state.getTlsContext().getSelectedProtocolVersion().name());
            return state.getTlsContext().getSelectedProtocolVersion() == toTest;
        }
    }

    private List<SignatureAndHashAlgorithm> getTls13SignatureAndHashAlgorithms() {
        List<SignatureAndHashAlgorithm> algos = new LinkedList<>();
        algos.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA256));
        algos.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA384));
        algos.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512));
        algos.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256));
        algos.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA384));
        algos.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA512));
        algos.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS, HashAlgorithm.SHA256));
        algos.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS, HashAlgorithm.SHA384));
        algos.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS, HashAlgorithm.SHA512));
        return algos;
    }

    private List<CipherSuite> getTls13Suite() {
        List<CipherSuite> tls13Suites = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.isTLS13()) {
                tls13Suites.add(suite);
            }
        }
        return tls13Suites;
    }

}
