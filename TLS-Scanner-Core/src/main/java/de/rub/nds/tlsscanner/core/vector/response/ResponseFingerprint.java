/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.response;

import com.fasterxml.jackson.annotation.JsonIgnore;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
public class ResponseFingerprint {
    @XmlElementWrapper @XmlElementRef @JsonIgnore private List<ProtocolMessage> messageList;

    @XmlElementWrapper
    @XmlElements(value = {@XmlElement(type = Record.class, name = "Record")})
    @JsonIgnore
    private List<Record> recordList;

    private String stringRepresentation;

    private SocketState socketState;

    /** Default constructor for ResponseFingerprint. */
    public ResponseFingerprint() {}

    /**
     * Constructs a ResponseFingerprint with the specified parameters.
     *
     * @param messageList List of protocol messages in the response
     * @param recordList List of records in the response
     * @param socketState The state of the socket after the response
     */
    public ResponseFingerprint(
            List<ProtocolMessage> messageList, List<Record> recordList, SocketState socketState) {
        this.messageList = messageList;
        this.recordList = recordList;
        this.socketState = socketState;
        this.stringRepresentation = toHumanReadable();
    }

    /**
     * Gets the socket state of this response fingerprint.
     *
     * @return The socket state
     */
    public SocketState getSocketState() {
        return socketState;
    }

    /**
     * Gets the list of records in this response fingerprint.
     *
     * @return The list of records
     */
    public List<Record> getRecordList() {
        return recordList;
    }

    /**
     * Gets the list of protocol messages in this response fingerprint.
     *
     * @return The list of protocol messages
     */
    public List<ProtocolMessage> getMessageList() {
        return messageList;
    }

    @Override
    public String toString() {

        StringBuilder messages = new StringBuilder();
        for (ProtocolMessage someMessage : this.messageList) {
            messages.append(someMessage.toCompactString()).append(",");
        }
        StringBuilder records = new StringBuilder();
        for (Record someRecord : this.getRecordList()) {
            records.append(someRecord.getClass().getSimpleName()).append(",");
        }

        return "ResponseFingerprint[ Messages=["
                + messages.toString()
                + "], Records=["
                + records.toString()
                + "], SocketState="
                + socketState
                + ']';
    }

    /**
     * Generates a short string representation of this response fingerprint.
     *
     * @return A short string representation
     */
    public String toShortString() {
        StringBuilder messages = new StringBuilder();
        for (ProtocolMessage someMessage : this.messageList) {
            messages.append(someMessage.toShortString()).append(",");
        }
        return messages.append("|").append(socketState).toString();
    }

    /**
     * Generates a human-readable string representation of this response fingerprint.
     *
     * @return A human-readable string representation
     */
    public String toHumanReadable() {
        StringBuilder resultString = new StringBuilder();
        for (ProtocolMessage msg : messageList) {
            ProtocolMessage message = msg;

            switch (message.getProtocolMessageType()) {
                case ALERT:
                    AlertMessage alert = (AlertMessage) message;
                    AlertDescription alertDescription =
                            AlertDescription.getAlertDescription(alert.getDescription().getValue());
                    AlertLevel alertLevel = AlertLevel.getAlertLevel(alert.getLevel().getValue());
                    if (alertDescription != null
                            && alertLevel != null
                            && alertLevel != AlertLevel.UNDEFINED) {
                        if (alertLevel == AlertLevel.FATAL) {
                            resultString.append("[").append(alertDescription.name()).append("]");
                        } else {
                            resultString.append("(").append(alertDescription.name()).append(")");
                        }
                    } else {
                        resultString
                                .append("{ALERT-")
                                .append(alert.getDescription().getValue())
                                .append("-")
                                .append(alert.getLevel())
                                .append("}");
                    }
                    break;
                case APPLICATION_DATA:
                    resultString.append("{APP}");
                    break;
                case CHANGE_CIPHER_SPEC:
                    resultString.append("{CCS}");
                    break;
                case HANDSHAKE:
                    if (message instanceof FinishedMessage) {
                        resultString.append("{FIN}");
                    } else {
                        resultString.append("{" + message.toCompactString() + "}");
                    }
                    break;
                case HEARTBEAT:
                    resultString.append("{HEARTBEAT}");
                    break;
                case UNKNOWN:
                    resultString.append("{UNKNOWN}");
                    break;
                default:
                    throw new UnsupportedOperationException("Unknown ProtocolMessageType");
            }
            resultString.append(" ");
        }
        if (recordList != null && recordList.size() > 0) {
            resultString.append(" [");
            for (Record record : recordList) {
                resultString.append("R(" + record.getLength().getValue() + "),");
            }
            // remove last commas
            resultString.deleteCharAt(resultString.length() - 1);
            resultString.append("]");
        }
        resultString.append(" ");
        if (socketState != null) {
            switch (socketState) {
                case CLOSED:
                    resultString.append("X");
                    break;
                case DATA_AVAILABLE:
                    resultString.append("$$$");
                    break;
                case IO_EXCEPTION:
                    resultString.append("§");
                    break;
                case SOCKET_EXCEPTION:
                    resultString.append("@");
                    break;
                case TIMEOUT:
                    resultString.append("T");
                    break;
                case UP:
                    resultString.append("U");
                    break;
                default: // should never occur as all ENUM types are handled
                    throw new UnsupportedOperationException("Unknown Socket State");
            }
        }
        return resultString.toString();
    }

    /**
     * Overrides the built-in hashCode() function. toString().hashCode() assures same hashes for
     * responses with essentially the same content but differences in their record bytes.
     *
     * @return The hash of the string representation
     */
    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    /**
     * Returns whether two ResponseFingerprints are equal using the {@link FingerprintChecker}.
     *
     * @param obj ResponseFingerprint to compare this one to
     * @return True, if both ResponseFingerprints are equal
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ResponseFingerprint)) {
            return false;
        }
        EqualityError equalityError =
                FingerprintChecker.checkEquality(this, (ResponseFingerprint) obj);
        return equalityError == EqualityError.NONE || equalityError == EqualityError.RECORD_CONTENT;
    }

    /**
     * Checks if this response fingerprint is compatible with another fingerprint. TODO: This does
     * not check record layer compatibility.
     *
     * @param fingerprint The fingerprint to compare with
     * @return true if the fingerprints are compatible, false otherwise
     */
    public boolean areCompatible(ResponseFingerprint fingerprint) {
        if (socketState != SocketState.TIMEOUT
                && fingerprint.getSocketState() != SocketState.TIMEOUT) {
            if (fingerprint.getSocketState() != socketState) {
                return false;
            }
        }
        int minNumberOfMessages = fingerprint.getMessageList().size();
        if (this.messageList.size() < minNumberOfMessages) {
            minNumberOfMessages = this.messageList.size();
        }
        for (int i = 0; i < minNumberOfMessages; i++) {
            ProtocolMessage messageOne = this.getMessageList().get(i);
            ProtocolMessage messageTwo = fingerprint.getMessageList().get(i);
            if (!checkMessagesAreRoughlyEqual(messageOne, messageTwo)) {
                return false;
            }
        }
        return true;
    }

    private boolean checkMessagesAreRoughlyEqual(
            ProtocolMessage messageOne, ProtocolMessage messageTwo) {
        if (!messageOne.getClass().equals(messageTwo.getClass())) {
            return false;
        }
        if (messageOne instanceof AlertMessage && messageTwo instanceof AlertMessage) {
            // Both are alerts
            AlertMessage alertOne = (AlertMessage) messageOne;
            AlertMessage alertTwo = (AlertMessage) messageTwo;
            if (alertOne.getDescription().getValue() != alertTwo.getDescription().getValue()
                    || alertOne.getLevel().getValue() != alertTwo.getLevel().getValue()) {
                return false;
            }
        }
        // nothing more to check?
        return true;
    }

    /**
     * Gets the string representation of this response fingerprint.
     *
     * @return The string representation
     */
    public String getStringRepresentation() {
        return stringRepresentation;
    }
}
