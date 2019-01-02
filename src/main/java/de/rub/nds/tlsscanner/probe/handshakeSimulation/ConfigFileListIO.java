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

public class ConfigFileListIO {

    private ConfigFileListIO() {
    }

    private static JAXBContext contextSingleton;

    private static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (contextSingleton == null) {
            contextSingleton = JAXBContext.newInstance(ConfigFileList.class);
        }
        return contextSingleton;
    }

    public static void write(ConfigFileList configFileList, File configFile) {
        try (OutputStream os = new FileOutputStream(configFile)) {
            JAXBContext context = getJAXBContext();
            Marshaller m = context.createMarshaller();
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            m.marshal(configFileList, os);
        } catch (JAXBException | IOException ex) {
            throw new RuntimeException("Could not format XML " + ex);
        }
    }

    public static ConfigFileList read(InputStream stream) {
        ConfigFileList configFileList = JAXB.unmarshal(stream, ConfigFileList.class);
        return configFileList;
    }
}
