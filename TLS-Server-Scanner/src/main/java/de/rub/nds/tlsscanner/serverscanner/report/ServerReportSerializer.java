/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.serverscanner.converter.Asn1CertificateSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.Asn1FieldSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CertificateSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CustomDhPublicKeySerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CustomDsaPublicKeySerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CustomEcPublicKeySerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CustomRsaPublicKeySerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.HttpsHeaderSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.PointSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.ResponseFingerprintSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.VectorSerializer;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import org.apache.logging.log4j.LogManager;

public class ServerReportSerializer {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger();

    public static void serialize(File outputFile, ScanReport scanReport) {
        try {
            ObjectMapper mapper = new ObjectMapper();

            SimpleModule module = new SimpleModule();
            module.addSerializer(new ByteArraySerializer());
            module.addSerializer(new ResponseFingerprintSerializer());
            module.addSerializer(new CertificateSerializer());
            module.addSerializer(new Asn1CertificateSerializer());
            module.addSerializer(new CustomDhPublicKeySerializer());
            module.addSerializer(new CustomEcPublicKeySerializer());
            module.addSerializer(new CustomRsaPublicKeySerializer());
            module.addSerializer(new CustomDsaPublicKeySerializer());
            module.addSerializer(new VectorSerializer());
            module.addSerializer(new PointSerializer());
            module.addSerializer(new HttpsHeaderSerializer());
            module.addSerializer(new Asn1FieldSerializer());

            mapper.registerModule(module);
            mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
            mapper.configOverride(BigDecimal.class).setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));
            mapper.writeValue(outputFile, scanReport);
        } catch (IOException ex) {
            LOGGER.error(ex);
        }
    }
}
