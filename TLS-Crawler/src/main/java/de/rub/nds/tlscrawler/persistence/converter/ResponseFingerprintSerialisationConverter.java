/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import java.io.IOException;

/**
 *
 * @author robert
 */
public class ResponseFingerprintSerialisationConverter extends StdSerializer<ResponseFingerprint> {
    
    public ResponseFingerprintSerialisationConverter() {
        super(ResponseFingerprint.class);
    }

    /**
     * TODO This simplifies the ResponseFingerprint quite a bit. For the long
     * term we should create a better more detailed serilisation
     *
     * @param responseFingerprint
     * @param jsonGenerator
     * @param serializerProvider
     * @throws IOException
     */
    @Override
    public void serialize(ResponseFingerprint responseFingerprint, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("socketState", responseFingerprint.getSocketState().name());
        jsonGenerator.writeNumberField("numberOfMessagesReceived", responseFingerprint.getNumberOfMessageReceived());
        jsonGenerator.writeNumberField("numberOfRecordsReceived", responseFingerprint.getNumberRecordsReceived());
        jsonGenerator.writeBooleanField("receivedTransportHandlerException", responseFingerprint.isReceivedTransportHandlerException());
        jsonGenerator.writeArrayFieldStart("receivedMessages");
        for (ProtocolMessage message : responseFingerprint.getMessageList()) {
            jsonGenerator.writeString(message.toCompactString());
        }
        jsonGenerator.writeEndArray();
        jsonGenerator.writeEndObject();
    }
}
