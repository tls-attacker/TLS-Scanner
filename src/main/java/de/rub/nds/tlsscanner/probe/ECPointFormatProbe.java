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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ECPointFormatResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class ECPointFormatProbe extends TlsProbe {

    public ECPointFormatProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.EC_POINT_FORMAT, scannerConfig, 0);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<CipherSuite> ourECDHCipherSuites = new LinkedList<>();
            for (CipherSuite cipherSuite : CipherSuite.values()) {
                if (cipherSuite.name().contains("TLS_ECDH")) {
                    ourECDHCipherSuites.add(cipherSuite);
                }
            }

            List<NamedGroup> groups = new LinkedList<>();
            groups.addAll(Arrays.asList(NamedGroup.values()));
            Config config = getScannerConfig().createConfig();
            config.setDefaultClientSupportedCiphersuites(ourECDHCipherSuites);
            config.setHighestProtocolVersion(ProtocolVersion.TLS12);
            config.setEnforceSettings(true);
            config.setAddServerNameIndicationExtension(true);
            config.setAddEllipticCurveExtension(true);
            config.setAddECPointFormatExtension(true);
            config.setAddSignatureAndHashAlgorithmsExtension(true);
            config.setAddRenegotiationInfoExtension(true);
            config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
            config.setQuickReceive(true);
            config.setEarlyStop(true);
            config.setStopActionsAfterFatal(true);
            config.setDefaultClientNamedGroups(groups);
            State state = new State(config);
            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
                if (state.getTlsContext().getServerPointFormatsList() != null) {
                    return (new ECPointFormatResult(state.getTlsContext().getServerPointFormatsList()));
                } else {
                    // no extension means only uncompressed
                    List<ECPointFormat> format = new LinkedList<>();
                    format.add(ECPointFormat.UNCOMPRESSED);
                    return (new ECPointFormatResult(format));
                }
            }
            LOGGER.debug("Unable to determine supported point formats");
            return (new ECPointFormatResult(null));
        } catch (Exception E) {
            return new ECPointFormatResult(null);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new ECPointFormatResult(null);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

}
