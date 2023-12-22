/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.passive;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.scanner.core.passive.StatExtractor;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import java.util.List;

public class EcPublicKeyExtractor extends StatExtractor<State, Point> {

    public EcPublicKeyExtractor() {
        super(TrackableValueType.ECDHE_PUBKEY);
    }

    @Override
    public void extract(State state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        List<ProtocolMessage> allReceivedMessages =
                WorkflowTraceResultUtil.getAllReceivedMessagesOfType(
                        trace, ProtocolMessageType.HANDSHAKE);
        if (state.getRunningMode() == RunningModeType.CLIENT) {
            for (ProtocolMessage message : allReceivedMessages) {
                if (message instanceof ECDHEServerKeyExchangeMessage) {
                    NamedGroup group =
                            NamedGroup.getNamedGroup(
                                    ((ECDHEServerKeyExchangeMessage) message)
                                            .getNamedGroup()
                                            .getValue());
                    byte[] pointBytes =
                            ((ECDHEServerKeyExchangeMessage) message).getPublicKey().getValue();
                    put(
                            PointFormatter.formatFromByteArray(
                                    (NamedEllipticCurveParameters) group.getGroupParameters(),
                                    pointBytes));
                }
            }
        } else {
            for (ProtocolMessage message : allReceivedMessages) {
                if (message instanceof ECDHClientKeyExchangeMessage) {
                    NamedGroup group = state.getTlsContext().getChooser().getSelectedNamedGroup();
                    byte[] pointBytes =
                            ((ECDHClientKeyExchangeMessage) message).getPublicKey().getValue();
                    put(
                            PointFormatter.formatFromByteArray(
                                    (NamedEllipticCurveParameters) group.getGroupParameters(),
                                    pointBytes));
                }
            }
        }
    }
}
