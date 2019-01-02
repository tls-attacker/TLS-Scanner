/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import org.apache.logging.log4j.LogManager;

public class TlsClientConfigIO {

    static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(TlsClientConfigIO.class.getName());

    private TlsClientConfigIO() {
    }
    
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
        } catch (JAXBException | IOException  ex) {
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
