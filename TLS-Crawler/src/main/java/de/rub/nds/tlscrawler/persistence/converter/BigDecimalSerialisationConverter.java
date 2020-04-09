/*
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.attacks.general.Vector;
import java.io.IOException;
import java.math.BigDecimal;
import java.text.DecimalFormat;

public class BigDecimalSerialisationConverter extends StdSerializer<BigDecimal> {

    public BigDecimalSerialisationConverter() {
        super(BigDecimal.class);
    }

    @Override
    public void serialize(BigDecimal decimal, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        DecimalFormat decimalFormat = new DecimalFormat();
        decimalFormat.setMaximumFractionDigits(24);
        jsonGenerator.writeString(decimalFormat.format(decimal));
    }
}
