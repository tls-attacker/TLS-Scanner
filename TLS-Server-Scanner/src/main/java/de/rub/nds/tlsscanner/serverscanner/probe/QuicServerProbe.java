/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsscanner.core.probe.QuicProbe;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class QuicServerProbe<
                ConfigSelector, Report extends TlsScanReport, Result extends ProbeResult<Report>>
        extends QuicProbe<Report, Result> {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final ConfigSelector configSelector;

    /**
     * Attempts to extract an extension from the last Server Hello or Encrypted Extensions message
     * to cover both TLS 1.2 and 1.3 . Server Hellos are prioritized over Encrypted Extension
     * messages
     *
     * @param  <T> The concrete extension class type
     * @param workflowTrace The executed workflow trace
     * @param extensionClass The requested extension class
     * @return The requested extension or null if no such extension was received
     */
    protected <T extends ExtensionMessage> T getNegotiatedExtension(
            WorkflowTrace workflowTrace, Class<T> extensionClass) {
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace)) {
            ServerHelloMessage serverHello =
                    (ServerHelloMessage)
                            WorkflowTraceUtil.getLastReceivedMessage(
                                    HandshakeMessageType.SERVER_HELLO, workflowTrace);
            if (serverHello.getExtension(extensionClass) != null) {
                return serverHello.getExtension(extensionClass);
            }
        }

        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.ENCRYPTED_EXTENSIONS, workflowTrace)) {
            EncryptedExtensionsMessage encryptedExtensions =
                    (EncryptedExtensionsMessage)
                            WorkflowTraceUtil.getLastReceivedMessage(
                                    HandshakeMessageType.ENCRYPTED_EXTENSIONS, workflowTrace);
            if (encryptedExtensions.getExtension(extensionClass) != null) {
                return encryptedExtensions.getExtension(extensionClass);
            }
        }

        return null;
    }

    protected QuicServerProbe(
            ParallelExecutor parallelExecutor, ProbeType type, ConfigSelector configSelector) {
        super(parallelExecutor, type);
        this.configSelector = configSelector;
    }
}
