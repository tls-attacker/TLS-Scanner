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
     * Drops the greeting a STARTTLS server sends unprompted after the handshake, so that two
     * responses are compared on what the scanner actually provoked.
     *
     * <p>Only leading application data is dropped, and only for a protocol whose {@link
     * StarttlsType#sendsUnpromptedPostHandshakeGreeting()} says it sends one. Everything the server
     * sends in reply to the scanner's own record follows the greeting, so a genuine oracle is left
     * intact: an alert, a close, or application data that comes after anything else is all still
     * fingerprinted. A response that is nothing but the greeting becomes an empty message list,
     * which is the truthful account of a connection where the server answered the vector with
     * silence.
     *
     * @param state the state the response was read from
     * @param messages the messages the receiving action collected
     * @return the messages without a leading unprompted greeting
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

    /**
     * How many messages the greeting filter removed from the front of the list.
     *
     * @param before the messages the receiving action collected
     * @param after the messages left after the greeting was dropped
     * @return the number of messages dropped
     */
    private static int countDropped(List<ProtocolMessage> before, List<ProtocolMessage> after) {
        if (before == null || after == null) {
            return 0;
        }
        return before.size() - after.size();
    }

    /**
     * Drops the records that carried the unprompted greeting.
     *
     * <p>The message list is filtered on its own, but a fingerprint compares record counts too, so
     * leaving the records behind only moves the difference from {@code MESSAGE_COUNT} to {@code
     * RECORD_COUNT}. The greeting arrives in its own records at the front of the response, one per
     * message it was parsed into, so dropping as many leading records as there were greeting
     * messages leaves exactly the records the scanner provoked.
     *
     * @param records the records the receiving action collected
     * @param droppedMessages how many leading messages were dropped as greeting
     * @return the records without the leading greeting
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
