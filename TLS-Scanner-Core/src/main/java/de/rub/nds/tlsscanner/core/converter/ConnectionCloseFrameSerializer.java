/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import java.io.IOException;

public class ConnectionCloseFrameSerializer extends StdSerializer<ConnectionCloseFrame> {

    public ConnectionCloseFrameSerializer() {
        super(ConnectionCloseFrame.class);
    }

    @Override
    public void serialize(
            ConnectionCloseFrame frame,
            JsonGenerator jsonGenerator,
            SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeString(frame.toString());
    }
}
