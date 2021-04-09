/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.CompressionsResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class CompressionsProbe extends TlsProbe {

    public CompressionsProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.COMPRESSIONS, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<CompressionMethod> compressions = getSupportedCompressionMethods();
            return new CompressionsResult(compressions);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new CompressionsResult(null);
        }
    }

    private List<CompressionMethod> getSupportedCompressionMethods() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.values());
        List<CompressionMethod> toTestList = new ArrayList<>(Arrays.asList(CompressionMethod.values()));

        CompressionMethod selectedCompressionMethod;
        List<CompressionMethod> supportedCompressionMethods = new LinkedList<>();
        do {
            selectedCompressionMethod = testCompressionMethods(toTestList, tlsConfig);
            if (!toTestList.contains(selectedCompressionMethod)) {
                LOGGER.debug("Server chose a CompressionMethod we did not offer!");
                break;
            }
            if (selectedCompressionMethod != null) {
                supportedCompressionMethods.add(selectedCompressionMethod);
                toTestList.remove(selectedCompressionMethod);
            }
        } while (selectedCompressionMethod != null || toTestList.size() > 0);
        return supportedCompressionMethods;
    }

    private CompressionMethod testCompressionMethods(List<CompressionMethod> compressionList, Config tlsConfig) {
        tlsConfig.setDefaultClientSupportedCompressionMethods(compressionList);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext().getSelectedCompressionMethod();
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CompressionsResult(null);
    }
}
