/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.KeyDeserializer;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.io.IOException;

public class AnalyzedPropertyKeyDeserializer extends KeyDeserializer {
    @Override
    public Object deserializeKey(String key, DeserializationContext ctxt) throws IOException {
        if (key == null) {
            return null;
        }
        try {
            return TlsAnalyzedProperty.valueOf(key);
        } catch (IllegalArgumentException e) {
            try {
                return QuicAnalyzedProperty.valueOf(key);
            } catch (IllegalArgumentException e2) {
                // If the key is not found, throw an IOException
                throw new IOException("Unknown AnalyzedProperty key: " + key, e2);
            }
        }
    }
}
