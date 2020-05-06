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
import java.util.Iterator;
import java.util.List;

/**
 *
 * @author robert
 */
public class ResponseFingerprintDeserializer extends StdDeserializer<ResponseFingerprint> {

    public ResponseFingerprintDeserializer() {
        super(ResponseFingerprint.class);
    }

    @Override
    public ResponseFingerprint deserialize(JsonParser jp, DeserializationContext dc) throws IOException, JsonProcessingException {
        JsonNode node = jp.getCodec().readTree(jp);
        String socketState = node.get("socketState").asText();
        //System.out.println(socketState);
        List<String> books = node.findValuesAsText("receivedMessages");
        for (String book : books) {
            //System.out.println(book);
        }
        

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
