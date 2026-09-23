/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.response;

import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.util.List;

/** Utility class for extracting response fingerprints from TLS-Attacker states and actions. */
public class ResponseExtractor {

    /**
     * Extracts a response fingerprint from the given state and receiving action.
     *
     * @param state The TLS-Attacker state
     * @param action The receiving action containing the response
     * @return A ResponseFingerprint containing the messages, records, and socket state
     */
    public static ResponseFingerprint getFingerprint(State state, ReceivingAction action) {
        List<ProtocolMessage> receivedMessages = action.getReceivedMessages();
        List<ProtocolMessage> messageList = withoutUnpromptedGreeting(state, receivedMessages);
        List<Record> recordList =
                withoutUnpromptedGreetingRecords(
                        action.getReceivedRecords(), countDropped(receivedMessages, messageList));
        SocketState socketState = extractSocketState(state);
        return new ResponseFingerprint(messageList, recordList, socketState);
    }

    /**
     * Extracts a response fingerprint from the last receiving action in the given state.
     *
     * @param state The TLS-Attacker state containing the workflow trace
     * @return A ResponseFingerprint from the last receiving action
     */
    public static ResponseFingerprint getFingerprint(State state) {
        ReceivingAction action = state.getWorkflowTrace().getLastReceivingAction();
        return getFingerprint(state, action);
    }

    /**
     * Drops the leading application data a STARTTLS server sends unprompted after the handshake, so
     * fingerprints only compare what the scanner provoked.
     */
    private static List<ProtocolMessage> withoutUnpromptedGreeting(
            State state, List<ProtocolMessage> messages) {
        if (messages == null || messages.isEmpty() || state.getConfig() == null) {
            return messages;
        }
        StarttlsType starttlsType = state.getConfig().getStarttlsType();
        if (starttlsType == null || !starttlsType.sendsUnpromptedPostHandshakeGreeting()) {
            return messages;
        }
        int firstProvoked = 0;
        while (firstProvoked < messages.size()
                && messages.get(firstProvoked) instanceof ApplicationMessage) {
            firstProvoked++;
        }
        return messages.subList(firstProvoked, messages.size());
    }

    private static int countDropped(List<ProtocolMessage> before, List<ProtocolMessage> after) {
        if (before == null || after == null) {
            return 0;
        }
        return before.size() - after.size();
    }

    /**
     * Drops the greeting's records too, one per dropped message, so the record count stays
     * comparable.
     */
    private static List<Record> withoutUnpromptedGreetingRecords(
            List<Record> records, int droppedMessages) {
        if (records == null || droppedMessages <= 0) {
            return records;
        }
        return records.subList(Math.min(droppedMessages, records.size()), records.size());
    }

    private static SocketState extractSocketState(State state) {
        if (state.getTlsContext().getTransportHandler() instanceof TcpTransportHandler) {
            SocketState socketState =
                    (((TcpTransportHandler) (state.getTlsContext().getTransportHandler()))
                            .getSocketState());
            return socketState;
        } else {
            return null;
        }
    }

    private ResponseExtractor() {}
}
