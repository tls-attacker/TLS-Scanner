/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

import de.rub.nds.modifiablevariable.util.XMLPrettyPrinter;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactoryConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.xml.sax.SAXException;

public class TlsClientConfigIO {
    
    static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(TlsClientConfigIO.class.getName());

    public TlsClientConfigIO() {
    }

    public void writeConfigToFile(TlsClientConfig clientConfig, File configFile) {
        OutputStream os = null;
        try {
            os = new FileOutputStream(configFile);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(TlsClientConfigIO.class.getName()).log(Level.SEVERE, null, ex);
        }
        ByteArrayOutputStream tempStream = new ByteArrayOutputStream();
        JAXB.marshal(clientConfig, tempStream);
        try {
            os.write(XMLPrettyPrinter.prettyPrintXML(new String(tempStream.toByteArray())).getBytes());
        } catch (IOException | TransformerException | XPathExpressionException | XPathFactoryConfigurationException
                | ParserConfigurationException | SAXException ex) {
            throw new RuntimeException("Could not format XML");
        }
    }
    
    public TlsClientConfig readConfigFromFile(File configFile) {
        TlsClientConfig clientConfig = JAXB.unmarshal(configFile, TlsClientConfig.class);
        return clientConfig;
    }
    
    public List<File> getClientConfigFileList(String path) {
        List<File> fileList = new LinkedList<>();
        try {
            for (String filename : getResourceFiles(path)) {
                File configFile = new File(getResourcePath(path) + "/" + filename);
                fileList.add(configFile);
            }
        } catch (IOException ex) {
            Logger.getLogger(TlsClientConfigIO.class.getName()).log(Level.SEVERE, null, ex);
        }
        return fileList;
    }
    
    private List<String> getResourceFiles(String path) throws IOException {
        List<String> filenames = new ArrayList<>();
        InputStream in = getResourceAsStream(path);
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        String resource;
        while ((resource = br.readLine()) != null) {
            filenames.add(resource);
        }
        return filenames;
    }
    
    private String getResourcePath(String resource) {
        String path = getContextClassLoader().getResource(resource).getPath();
        return path;
    }
    
    private InputStream getResourceAsStream(String resource) {
        InputStream in = getContextClassLoader().getResourceAsStream(resource);
        return in == null ? getClass().getResourceAsStream(resource) : in;
    }
    
    private ClassLoader getContextClassLoader() {
        return Thread.currentThread().getContextClassLoader();
    }
}
