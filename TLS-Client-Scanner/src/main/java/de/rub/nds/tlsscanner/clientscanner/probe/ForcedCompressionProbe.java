/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import javax.print.attribute.standard.Compression;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class ForcedCompressionProbe extends BaseProbe {
    public ForcedCompressionProbe(Orchestrator orchestrator) {
        super(orchestrator);
    }

    @Override
    protected ProbeRequirements getRequirements() {
        return null;
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        Config config = state.getConfig();
        // need to set contexts compression method correctly for hello
        state.getTlsContext().setSelectedCompressionMethod(CompressionMethod.NULL);
        config.setDefaultServerSupportedCompressionMethods(CompressionMethod.DEFLATE, CompressionMethod.LZS);
        config.setDefaultSelectedCompressionMethod(CompressionMethod.DEFLATE);
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config, true);
        executeState(state, dispatchInformation);
        if (state.getTlsContext().getSelectedCompressionMethod() == CompressionMethod.NULL) {
            throw new DispatchException("Failed to set compression method; NULL got set...");
        }
        return new ForcedCompressionResult(state);
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class ForcedCompressionResult extends ClientProbeResult {
        public final boolean vulnerable;

        public ForcedCompressionResult(State state) {
            vulnerable = state.getWorkflowTrace().executedAsPlanned();
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(ForcedCompressionProbe.class, this);
        }
    }

}
