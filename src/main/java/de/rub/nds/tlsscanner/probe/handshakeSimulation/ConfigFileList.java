/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

import java.io.File;
import java.io.InputStream;
import java.io.Serializable;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ConfigFileList implements Serializable {

    public static final String FILE_NAME = "client_config_file_list.xml";

    private List<String> files;

    public static ConfigFileList loadConfigFileList(String resourcePath) {
        InputStream stream = ConfigFileList.class.getResourceAsStream(resourcePath);
        return ConfigFileListIO.read(stream);
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
