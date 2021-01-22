/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElement;
import java.io.IOException;

/**
 *
 * @author robert
 */
public class FieldElementDeserializer extends StdDeserializer<FieldElement> {

    public FieldElementDeserializer() {
        super(FieldElement.class);
    }

    @Override
    public FieldElement deserialize(JsonParser jp, DeserializationContext dc) throws IOException, JsonProcessingException {
//        JsonNode node = jp.getCodec().readTree(jp);
//        String socketState = node.get("socketState").asText();
//        System.out.println(socketState);
//        List<String> receivedMessages = node.findValuesAsText("receivedMessages");
//        for (String book : receivedMessages) {
//            System.out.println(book);
//        }
        

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
