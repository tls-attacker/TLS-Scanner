/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameterEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import java.io.IOException;

public class QuicTransportParametersSerializer extends StdSerializer<QuicTransportParameters> {

    public QuicTransportParametersSerializer() {
        super(QuicTransportParameters.class);
    }

    @Override
    public void serialize(
            QuicTransportParameters quicTransportParameters,
            JsonGenerator jsonGenerator,
            SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeStartObject();
        if (quicTransportParameters.getOriginalDestinationConnectionId() != null) {
            jsonGenerator.writeStringField(
                    "originalDestinationConnectionId",
                    byteArrayToString(
                            quicTransportParameters.getOriginalDestinationConnectionId()));
        }
        if (quicTransportParameters.getInitialSourceConnectionId() != null) {
            jsonGenerator.writeStringField(
                    "initialSourceConnectionId",
                    byteArrayToString(quicTransportParameters.getInitialSourceConnectionId()));
        }
        if (quicTransportParameters.getRetrySourceConnectionId() != null) {
            jsonGenerator.writeStringField(
                    "retrySourceConnectionId",
                    byteArrayToString(quicTransportParameters.getRetrySourceConnectionId()));
        }
        if (quicTransportParameters.getMaxIdleTimeout() != null) {
            jsonGenerator.writeNumberField(
                    "maxIdleTimeout", quicTransportParameters.getMaxIdleTimeout());
        }
        if (quicTransportParameters.getMaxUdpPayloadSize() != null) {
            jsonGenerator.writeNumberField(
                    "maxUdpPayloadSize", quicTransportParameters.getMaxUdpPayloadSize());
        }
        if (quicTransportParameters.getInitialMaxData() != null) {
            jsonGenerator.writeNumberField(
                    "initialMaxData", quicTransportParameters.getInitialMaxData());
        }
        if (quicTransportParameters.getInitialMaxStreamDataBidiLocal() != null) {
            jsonGenerator.writeNumberField(
                    "initialMaxStreamDataBidiLocal",
                    quicTransportParameters.getInitialMaxStreamDataBidiLocal());
        }
        if (quicTransportParameters.getInitialMaxStreamDataBidiRemote() != null) {
            jsonGenerator.writeNumberField(
                    "initialMaxStreamDataBidiRemote",
                    quicTransportParameters.getInitialMaxStreamDataBidiRemote());
        }
        if (quicTransportParameters.getInitialMaxStreamDataUni() != null) {
            jsonGenerator.writeNumberField(
                    "initialMaxStreamDataUni",
                    quicTransportParameters.getInitialMaxStreamDataUni());
        }
        if (quicTransportParameters.getInitialMaxStreamsBidi() != null) {
            jsonGenerator.writeNumberField(
                    "initialMaxStreamsBidi", quicTransportParameters.getInitialMaxStreamsBidi());
        }
        if (quicTransportParameters.getInitialMaxStreamsUni() != null) {
            jsonGenerator.writeNumberField(
                    "initialMaxStreamsUni", quicTransportParameters.getInitialMaxStreamsUni());
        }
        if (quicTransportParameters.getAckDelayExponent() != null) {
            jsonGenerator.writeNumberField(
                    "ackDelayExponent", quicTransportParameters.getAckDelayExponent());
        }
        if (quicTransportParameters.getMaxAckDelay() != null) {
            jsonGenerator.writeNumberField("maxAckDelay", quicTransportParameters.getMaxAckDelay());
        }
        jsonGenerator.writeBooleanField(
                "disableActiveMigration", quicTransportParameters.isDisableActiveMigration());

        for (QuicTransportParameterEntry extraEntry : quicTransportParameters.getExtraEntries()) {
            if (extraEntry.getEntryType() != null && extraEntry.getEntryValue() != null) {
                jsonGenerator.writeStringField(
                        extraEntry.getEntryType().name(),
                        byteArrayToString(extraEntry.getEntryValue().getValue()));
            }
        }
        if (quicTransportParameters.getPreferredAddress() != null) {
            jsonGenerator.writeFieldName("preferredAddress");
            jsonGenerator.writeStartObject();
            if (quicTransportParameters.getPreferredAddress().getIpv4Address() != null) {
                jsonGenerator.writeStringField(
                        "ipv4",
                        quicTransportParameters
                                .getPreferredAddress()
                                .getIpv4Address()
                                .getHostAddress());
            }
            jsonGenerator.writeNumberField(
                    "ipv4Port", quicTransportParameters.getPreferredAddress().getIpv4Port());
            if (quicTransportParameters.getPreferredAddress().getIpv6Address() != null) {
                jsonGenerator.writeStringField(
                        "ipv6",
                        quicTransportParameters
                                .getPreferredAddress()
                                .getIpv6Address()
                                .getHostAddress());
            }
            jsonGenerator.writeNumberField(
                    "ipv6Port", quicTransportParameters.getPreferredAddress().getIpv6Port());

            if (quicTransportParameters.getPreferredAddress().getConnectionId() != null) {
                jsonGenerator.writeStringField(
                        "connectionId",
                        byteArrayToString(
                                quicTransportParameters.getPreferredAddress().getConnectionId()));
            }
            if (quicTransportParameters.getPreferredAddress().getStatelessResetToken() != null) {
                jsonGenerator.writeStringField(
                        "statelessResetToken",
                        byteArrayToString(
                                quicTransportParameters
                                        .getPreferredAddress()
                                        .getStatelessResetToken()));
            }
            jsonGenerator.writeEndObject();
        }
        jsonGenerator.writeEndObject();
    }

    private static String byteArrayToString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return ArrayConverter.bytesToHexString(bytes, false, false).replace(" ", "");
    }
}
