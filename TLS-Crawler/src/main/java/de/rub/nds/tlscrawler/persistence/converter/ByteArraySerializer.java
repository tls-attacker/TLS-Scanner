/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.IOException;

/**
 *
 * @author robert
 */
public class ByteArraySerializer extends StdSerializer<byte[]> {

    public ByteArraySerializer() {
        super(byte[].class);
    }

    @Override
    public void serialize(byte[] bytes, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(ArrayConverter.bytesToHexString(bytes, false, false).replace(" ", ""));
    }
}
