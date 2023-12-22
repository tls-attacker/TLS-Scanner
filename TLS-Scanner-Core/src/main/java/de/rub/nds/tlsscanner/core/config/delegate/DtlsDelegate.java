/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

public class DtlsDelegate extends Delegate {

    @Parameter(names = "-dtls", required = false, description = "Scan DTLS")
    private boolean dtls = false;

    public DtlsDelegate() {}

    public boolean isDTLS() {
        return dtls;
    }

    public void setDTLS(boolean dtls) {
        this.dtls = dtls;
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        if (dtls) {
            config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
            config.setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS12);

            if (config.getDefaultClientConnection() == null) {
                config.setDefaultClientConnection(new OutboundConnection());
            }
            if (config.getDefaultServerConnection() == null) {
                config.setDefaultServerConnection(new InboundConnection());
            }
            config.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.UDP);
            config.getDefaultServerConnection().setTransportHandlerType(TransportHandlerType.UDP);

            config.setDefaultLayerConfiguration(StackConfiguration.DTLS);
            config.setWorkflowExecutorType(WorkflowExecutorType.DTLS);
            config.setFinishWithCloseNotify(true);
            config.setIgnoreRetransmittedCssInDtls(true);
            config.setAddRetransmissionsToWorkflowTraceInDtls(true);
        }
    }
}
