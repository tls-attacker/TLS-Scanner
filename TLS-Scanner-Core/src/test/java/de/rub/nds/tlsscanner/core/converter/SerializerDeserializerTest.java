/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Tests for serializers and deserializers. Currently disabled due to issues with dependencies in
 * the test environment.
 */
public class SerializerDeserializerTest {

    private static ObjectMapper mapper;

    @BeforeAll
    public static void setupClass() {
        mapper = new ObjectMapper();
        mapper.setVisibility(PropertyAccessor.FIELD, Visibility.ANY);

        SimpleModule module = new SimpleModule();
        // Register just the ByteArray serializer and deserializer
        module.addSerializer(byte[].class, new ByteArraySerializer());
        module.addDeserializer(byte[].class, new ByteArrayDeserializer());

        mapper.registerModule(module);
    }

    @Test
    public void testByteArraySerializerDeserializer() throws IOException {
        byte[] original = new byte[] {1, 2, 3, 4, 5};
        byte[] serialized = serialize(original);
        byte[] deserialized = deserialize(serialized, byte[].class);
        assertArrayEquals(original, deserialized);
    }

    private <T> byte[] serialize(T value) throws IOException {
        SilentByteArrayOutputStream outputStream = new SilentByteArrayOutputStream();
        mapper.writeValue(outputStream, value);
        return outputStream.toByteArray();
    }

    private <T> T deserialize(byte[] serialized, Class<T> clazz) throws IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(serialized);
        return mapper.readValue(inputStream, clazz);
    }
}
