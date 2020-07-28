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
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author robert
 */
public class ExtractedValueContainerDeserializer extends StdDeserializer<ExtractedValueContainer> {

    public ExtractedValueContainerDeserializer() {
        super(ExtractedValueContainer.class);
    }

    @Override
    public ExtractedValueContainer deserialize(JsonParser jp, DeserializationContext dc) throws IOException, JsonProcessingException {
        JsonNode node = jp.getCodec().readTree(jp);
        TrackableValueType type = TrackableValueType.valueOf(node.get("type").asText());
        //System.out.println(socketState);
        //TODO THIS HAS TO HAVE A FULL IMPLEMENTATION
        return new ExtractedValueContainer(type);

    }
}
