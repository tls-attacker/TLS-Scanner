/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

import de.rub.nds.modifiablevariable.util.XMLPrettyPrinter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactoryConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.xml.sax.SAXException;

public class ConfigFileListIO {

    static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(ConfigFileListIO.class.getName());

    private ConfigFileListIO() {
    }

    public static void write(ConfigFileList configFileList, File file) {
        OutputStream os = null;
        try {
            os = new FileOutputStream(file);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(TlsClientConfigIO.class.getName()).log(Level.SEVERE, null, ex);
        }
        ByteArrayOutputStream tempStream = new ByteArrayOutputStream();
        JAXB.marshal(configFileList, tempStream);
        try {
            os.write(XMLPrettyPrinter.prettyPrintXML(new String(tempStream.toByteArray())).getBytes());
        } catch (IOException | TransformerException | XPathExpressionException | XPathFactoryConfigurationException | ParserConfigurationException | SAXException ex) {
            throw new RuntimeException("Could not format XML");
        }
    }

    public static ConfigFileList read(InputStream stream) {
        ConfigFileList configFileList = JAXB.unmarshal(stream, ConfigFileList.class);
        return configFileList;
    }
}
