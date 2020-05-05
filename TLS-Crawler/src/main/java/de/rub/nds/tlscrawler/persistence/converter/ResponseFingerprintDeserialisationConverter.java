/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author robert
 */
public class ResponseFingerprintDeserialisationConverter extends StdDeserializer<ResponseFingerprint> {
    
    public ResponseFingerprintDeserialisationConverter() {
        super(ResponseFingerprint.class);
    }

    @Override
    public ResponseFingerprint deserialize(JsonParser jp, DeserializationContext dc) throws IOException, JsonProcessingException {
//        JsonNode node = jp.getCodec().readTree(jp);
//        String socketState = node.get("socketState").asText();
//        int messageReceiveds = node.get("numberOfMessagesReceived").asInt();
//        int recordsReceiveds = node.get("numberOfRecordsReceived").asInt();
//        boolean encryptedAlert = node.get("encryptedAlert").asBoolean();
//        boolean receivedTransportHandlerException = node.get("false").asBoolean();
//        
//        List<String> answers = node.findValuesAsText("receivedMessages");
//        
//        
//        jsonGenerator.writeStartObject();
//        jsonGenerator.writeStringField("socketState", responseFingerprint.getSocketState().name());
//        jsonGenerator.writeNumberField("numberOfMessagesReceived", responseFingerprint.getNumberOfMessageReceived());
//        jsonGenerator.writeNumberField("numberOfRecordsReceived", responseFingerprint.getNumberRecordsReceived());
//        jsonGenerator.writeBooleanField("encryptedAlert", responseFingerprint.isEncryptedAlert());
//        jsonGenerator.writeBooleanField("receivedTransportHandlerException", responseFingerprint.isReceivedTransportHandlerException());
//        jsonGenerator.writeArrayFieldStart("receivedMessages");
//        for (ProtocolMessage message : responseFingerprint.getMessageList()) {
//            jsonGenerator.writeString(message.toCompactString());
//        }
//        jsonGenerator.writeEndArray();
//        jsonGenerator.writeEndObject();
return null;
    }
}
