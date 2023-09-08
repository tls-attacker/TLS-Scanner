/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ByteArraySerializer;
import de.rub.nds.tlsscanner.core.converter.Asn1CertificateSerializer;
import de.rub.nds.tlsscanner.core.converter.Asn1FieldSerializer;
import de.rub.nds.tlsscanner.core.converter.CertificateSerializer;
import de.rub.nds.tlsscanner.core.converter.CustomDhPublicKeySerializer;
import de.rub.nds.tlsscanner.core.converter.CustomDsaPublicKeySerializer;
import de.rub.nds.tlsscanner.core.converter.CustomEcPublicKeySerializer;
import de.rub.nds.tlsscanner.core.converter.CustomRsaPublicKeySerializer;
import de.rub.nds.tlsscanner.core.converter.HttpsHeaderSerializer;
import de.rub.nds.tlsscanner.core.converter.PointSerializer;
import de.rub.nds.tlsscanner.core.converter.ResponseFingerprintSerializer;
import de.rub.nds.tlsscanner.core.converter.VectorSerializer;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerReportSerializer {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void serialize(File outputFile, ServerReport scanReport) {
        try {
            ObjectMapper mapper = new ObjectMapper();

            SimpleModule module = new SimpleModule();
            module.addSerializer(new ByteArraySerializer());
            module.addSerializer(new ResponseFingerprintSerializer());
            module.addSerializer(new CertificateSerializer());
            module.addSerializer(new Asn1CertificateSerializer());
            module.addSerializer(new Asn1FieldSerializer());
            module.addSerializer(new CustomDhPublicKeySerializer());
            module.addSerializer(new CustomEcPublicKeySerializer());
            module.addSerializer(new CustomRsaPublicKeySerializer());
            module.addSerializer(new CustomDsaPublicKeySerializer());
            module.addSerializer(new VectorSerializer());
            module.addSerializer(new PointSerializer());
            module.addSerializer(new HttpsHeaderSerializer());

            mapper.registerModule(module);
            mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
            mapper.configOverride(BigDecimal.class)
                    .setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));
            mapper.writeValue(outputFile, scanReport);
        } catch (IOException ex) {
            LOGGER.error(ex);
        }
    }
}
