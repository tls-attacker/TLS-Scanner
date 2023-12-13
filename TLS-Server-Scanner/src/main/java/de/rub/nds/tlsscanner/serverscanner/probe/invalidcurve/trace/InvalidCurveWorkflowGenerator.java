/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.trace;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeDefaultPreMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.constants.InvalidCurveWorkflowType;

public class InvalidCurveWorkflowGenerator {

    private InvalidCurveWorkflowGenerator() {}

    public static WorkflowTrace generateWorkflow(
            InvalidCurveWorkflowType type,
            ModifiableByteArray serializedPublicKey,
            ModifiableByteArray pms,
            byte[] explicitPMS,
            Config tlsConfig) {
        switch (type) {
            case REGULAR:
                return prepareRegularTrace(serializedPublicKey, pms, explicitPMS, tlsConfig);
            case RENEGOTIATION:
                return prepareRenegotiationTrace(serializedPublicKey, pms, explicitPMS, tlsConfig);
            default:
                throw new IllegalArgumentException("Unknown InvalidCurveWorkflowType: " + type);
        }
    }

    private static WorkflowTrace prepareRegularTrace(
            ModifiableByteArray serializedPublicKey,
            ModifiableByteArray pms,
            byte[] explicitPMS,
            Config individualConfig) {
        if (individualConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13) {
            individualConfig.setDefaultSelectedCipherSuite(
                    individualConfig.getDefaultClientSupportedCipherSuites().get(0));
        }
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(individualConfig)
                        .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.CLIENT);
        if (individualConfig.getHighestProtocolVersion().isTLS13()) {
            // replace specific receive action with generic
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
            trace.addTlsAction(new GenericReceiveAction());

            ClientHelloMessage clientHello =
                    (ClientHelloMessage)
                            WorkflowTraceResultUtil.getFirstSentMessage(
                                    trace, HandshakeMessageType.CLIENT_HELLO);
            KeyShareExtensionMessage ksExt;
            for (ExtensionMessage ext : clientHello.getExtensions()) {
                if (ext instanceof KeyShareExtensionMessage) {
                    ksExt = (KeyShareExtensionMessage) ext;
                    // we use exactly one key share
                    ksExt.getKeyShareList().get(0).setPublicKey(serializedPublicKey);
                }
            }

            // TODO: use action / modification to influence key derivation for
            // TLS 1.3
            individualConfig.setDefaultPreMasterSecret(explicitPMS);
        } else {
            trace.addTlsAction(
                    new SendAction(
                            new ECDHClientKeyExchangeMessage(),
                            new ChangeCipherSpecMessage(),
                            new FinishedMessage()));
            trace.addTlsAction(new GenericReceiveAction());

            ECDHClientKeyExchangeMessage message =
                    (ECDHClientKeyExchangeMessage)
                            WorkflowTraceResultUtil.getFirstSentMessage(
                                    trace, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
            message.setPublicKey(serializedPublicKey);
            message.prepareComputations();
            message.getComputations().setPremasterSecret(pms);
        }

        return trace;
    }

    private static WorkflowTrace prepareRenegotiationTrace(
            ModifiableByteArray serializedPublicKey,
            ModifiableByteArray pms,
            byte[] explicitPMS,
            Config individualConfig) {
        WorkflowTrace trace;
        if (individualConfig.getHighestProtocolVersion().isTLS13()) {
            trace =
                    new WorkflowConfigurationFactory(individualConfig)
                            .createWorkflowTrace(
                                    WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
            trace.addTlsAction(
                    new ReceiveAction(
                            ActionOption.CHECK_ONLY_EXPECTED,
                            new NewSessionTicketMessage(individualConfig, false)));
            trace.addTlsAction(new ResetConnectionAction());

            // make sure no explicit PreMasterSecret is set upon execution
            ChangeDefaultPreMasterSecretAction noPMS = new ChangeDefaultPreMasterSecretAction();
            noPMS.setNewValue(new byte[0]);
            trace.getTlsActions().add(0, noPMS);

            // next ClientHello needs a PSKExtension
            individualConfig.setAddPreSharedKeyExtension(Boolean.TRUE);

            WorkflowTrace secondHandshake =
                    prepareRegularTrace(serializedPublicKey, pms, explicitPMS, individualConfig);

            // subsequent ClientHellos don't need a PSKExtension
            individualConfig.setAddPreSharedKeyExtension(Boolean.FALSE);

            // set explicit PreMasterSecret later on using an action
            ChangeDefaultPreMasterSecretAction clientPMS = new ChangeDefaultPreMasterSecretAction();
            clientPMS.setNewValue(explicitPMS);
            trace.addTlsAction(clientPMS);

            for (TlsAction action : secondHandshake.getTlsActions()) {
                trace.addTlsAction(action);
            }
        } else {
            individualConfig.setDefaultSelectedCipherSuite(
                    individualConfig.getDefaultClientSupportedCipherSuites().get(0));
            trace =
                    new WorkflowConfigurationFactory(individualConfig)
                            .createWorkflowTrace(
                                    WorkflowTraceType.CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION,
                                    RunningModeType.CLIENT);
            ECDHClientKeyExchangeMessage message =
                    (ECDHClientKeyExchangeMessage)
                            WorkflowTraceResultUtil.getLastSentMessage(
                                    trace, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
            message.setPublicKey(serializedPublicKey);
            message.prepareComputations();
            message.getComputations().setPremasterSecret(pms);

            // replace specific receive action with generic
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
            trace.addTlsAction(new GenericReceiveAction());
        }

        return trace;
    }
}
