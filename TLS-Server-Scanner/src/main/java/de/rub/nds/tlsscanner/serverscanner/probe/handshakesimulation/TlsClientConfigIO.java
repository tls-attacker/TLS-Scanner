/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation;

import jakarta.xml.bind.JAXB;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TlsClientConfigIO {

    private TlsClientConfigIO() {}

    private static JAXBContext contextSingleton;

    private static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (contextSingleton == null) {
            contextSingleton = JAXBContext.newInstance(TlsClientConfig.class);
        }
        return contextSingleton;
    }

    public static void write(TlsClientConfig clientConfig, File configFile) {
        try (OutputStream os = new FileOutputStream(configFile)) {
            JAXBContext context = getJAXBContext();
            Marshaller m = context.createMarshaller();
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            m.marshal(clientConfig, os);
        } catch (JAXBException | IOException ex) {
            throw new RuntimeException("Could not format XML " + ex);
        }
    }

    public static TlsClientConfig read(File configFile) {
        TlsClientConfig clientConfig = JAXB.unmarshal(configFile, TlsClientConfig.class);
        return clientConfig;
    }

    public static TlsClientConfig read(InputStream stream) {
        TlsClientConfig clientConfig = JAXB.unmarshal(stream, TlsClientConfig.class);
        return clientConfig;
    }
}
