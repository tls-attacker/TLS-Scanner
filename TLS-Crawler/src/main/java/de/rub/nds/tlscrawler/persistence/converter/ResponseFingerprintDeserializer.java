/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

/**
 * @author robert
 */
public class ResponseFingerprintDeserializer extends StdDeserializer<ResponseFingerprint> {

    public ResponseFingerprintDeserializer() {
        super(ResponseFingerprint.class);
    }

    @Override
    public ResponseFingerprint deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);
        String socketState = node.get("socketState").asText();
        ArrayNode arrayNode = (ArrayNode) node.get("receivedMessages");
        List<ProtocolMessage> messageList = new LinkedList<>();
        for (int i = 0; i < arrayNode.size(); i++) {
            String compactString = arrayNode.get(i).asText();
            if (compactString.startsWith("Alert")) {
                compactString = compactString.replace("Alert", "");
                compactString = compactString.replace(")", "");
                compactString = compactString.replace("(", "");
                String[] split = compactString.split(",");
                AlertLevel alertLevel = AlertLevel.valueOf(split[0]);
                AlertDescription alertDescription = AlertDescription.valueOf(split[1]);
                AlertMessage alertMessage = new AlertMessage();
                alertMessage.setConfig(alertLevel, alertDescription);
                alertMessage.setDescription(alertDescription.getValue());
                alertMessage.setLevel(alertLevel.getValue());
                messageList.add(alertMessage);
            } else if (compactString.equals("UNKNOWN_MESSAGE")) {
                messageList.add(new UnknownMessage());
            } else if (compactString.equals("SERVER_HELLO")) {
                messageList.add(new ServerHelloMessage());
            } else if (compactString.equals("CHANGE_CIPHER_SPEC")) {
                messageList.add(new ChangeCipherSpecMessage());
            } else if (compactString.equals("APPLICATION")) {
                messageList.add(new ApplicationMessage());
            } else {
                System.out.println(compactString);
            }
        }
        return new ResponseFingerprint(messageList, null, SocketState.valueOf(socketState));
    }
}
