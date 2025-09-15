/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import de.rub.nds.modifiablevariable.json.ModifiableVariableModule;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Utility class for converting between ServerReport and JSON. */
public class ServerReportJsonMapper {
    private static final Logger LOGGER = LogManager.getLogger();
    public final ObjectMapper objectMapper;

    /**
     * Creates StreamReadConstraints with project-specific settings. Use this method in other
     * mappers that need the same constraints.
     *
     * @return Configured StreamReadConstraints
     */
    public static StreamReadConstraints createStreamReadConstraints() {
        return StreamReadConstraints.builder()
                .maxStringLength(50_000_000) // 50MB for handling very large reports
                .maxNestingDepth(2000)
                .maxNumberLength(10000) // Max number of digits in numbers
                .maxNameLength(50000) // Max length for property names
                .build();
    }

    /** Constructs a ServerReportJsonMapper with configured ObjectMapper settings. */
    public ServerReportJsonMapper() {
        this.objectMapper = new ObjectMapper();
        // include ModifiableVariable module
        objectMapper.registerModule(new ModifiableVariableModule());
        objectMapper.setVisibility(ModifiableVariableModule.getFieldVisibilityChecker());

        // Apply the stream read constraints defined in the static method
        StreamReadConstraints streamReadConstraints = createStreamReadConstraints();
        objectMapper.getFactory().setStreamReadConstraints(streamReadConstraints);
        objectMapper.registerModule(new JodaModule());
        objectMapper.registerModules(ServerReport.getSerializerModules());
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
        objectMapper.setVisibility(PropertyAccessor.GETTER, JsonAutoDetect.Visibility.NONE);
        objectMapper.setVisibility(PropertyAccessor.SETTER, JsonAutoDetect.Visibility.NONE);
        objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

        objectMapper.configure(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION.mappedFeature(), true);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    /**
     * Converts a ServerReport to a JSON ObjectNode.
     *
     * @param report the ServerReport to convert
     * @return JsonNode representing the report
     */
    public ObjectNode toJsonNode(ServerReport report) {
        try {
            return objectMapper.valueToTree(report);
        } catch (Exception e) {
            LOGGER.error("Error serializing ServerReport to JSON", e);
            return objectMapper.createObjectNode();
        }
    }

    /**
     * Converts a JSON ObjectNode to a ServerReport.
     *
     * @param jsonNode the JSON to convert
     * @return the deserialized ServerReport
     */
    public ServerReport fromJsonNode(JsonNode jsonNode) {
        if (jsonNode == null) {
            return null;
        }
        try {
            String jsonString = objectMapper.writeValueAsString(jsonNode);
            return objectMapper.readValue(jsonString, ServerReport.class);
        } catch (IOException e) {
            LOGGER.error("Error deserializing ServerReport from JSON", e);
            return null;
        }
    }

    /**
     * Converts a ServerReport to a JSON string.
     *
     * @param report the ServerReport to convert
     * @return String containing the JSON representation
     */
    public String toJsonString(ServerReport report) {
        try {
            return objectMapper.writeValueAsString(report);
        } catch (Exception e) {
            LOGGER.error("Error serializing ServerReport to JSON string", e);
            return "{}";
        }
    }

    /**
     * Converts a JSON string to a ServerReport.
     *
     * @param jsonString the JSON string to convert
     * @return the deserialized ServerReport
     */
    public ServerReport fromJsonString(String jsonString) {
        if (jsonString == null || jsonString.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.readValue(jsonString, ServerReport.class);
        } catch (IOException e) {
            LOGGER.error("Error deserializing ServerReport from JSON string", e);
            return null;
        }
    }
}
