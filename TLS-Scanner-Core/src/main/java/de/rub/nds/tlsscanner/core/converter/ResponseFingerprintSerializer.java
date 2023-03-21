/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.io.IOException;

public class ResponseFingerprintSerializer extends StdSerializer<ResponseFingerprint> {

    public ResponseFingerprintSerializer() {
        super(ResponseFingerprint.class);
    }

    /**
     * TODO This simplifies the ResponseFingerprint quite a bit. For the long term we should create
     * a better more detailed serilisation
     *
     * @param responseFingerprint
     * @param jsonGenerator
     * @param serializerProvider
     * @throws IOException
     */
    @Override
    public void serialize(
            ResponseFingerprint responseFingerprint,
            JsonGenerator jsonGenerator,
            SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("socketState", responseFingerprint.getSocketState().name());
        jsonGenerator.writeNumberField(
                "numberOfMessagesReceived", responseFingerprint.getMessageList().size());
        jsonGenerator.writeNumberField(
                "numberOfRecordsReceived", responseFingerprint.getRecordList().size());
        jsonGenerator.writeArrayFieldStart("receivedMessages");
        for (ProtocolMessage message : responseFingerprint.getMessageList()) {
            jsonGenerator.writeString(message.toCompactString());
        }
        jsonGenerator.writeEndArray();
        jsonGenerator.writeEndObject();
    }
}
