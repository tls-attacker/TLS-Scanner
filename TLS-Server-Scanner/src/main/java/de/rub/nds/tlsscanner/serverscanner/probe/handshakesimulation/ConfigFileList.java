/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation;

import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.xml.stream.XMLStreamException;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ConfigFileList implements Serializable {

    public static final String FILE_NAME = "client_config_file_list.xml";

    private List<String> files;

    public static ConfigFileList loadConfigFileList(String resourcePath)
            throws JAXBException, IOException, XMLStreamException {
        try (InputStream stream = ConfigFileList.class.getResourceAsStream(resourcePath)) {
            return new ConfigFileListIO().read(stream);
        }
    }

    public void createConfigFileList(String folder) {
        File f = new File(folder);
        File[] fileArray = f.listFiles();
        Arrays.sort(fileArray);
        List<String> fileList = new LinkedList<>();
        for (File file : fileArray) {
            if (file.isFile()) {
                fileList.add(file.getName());
            }
        }
        this.files = fileList;
    }

    public List<String> getFiles() {
        return files;
    }

    public void setFiles(List<String> files) {
        this.files = files;
    }
}
