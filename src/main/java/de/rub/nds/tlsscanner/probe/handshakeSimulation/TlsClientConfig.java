/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.io.Serializable;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TlsClientConfig implements Serializable {
    
    private String type;   
    private String version;
    private Config config;
    private WorkflowTrace trace;
    private List<Integer> supportedRsaKeyLengthList;
    private List<Integer> supportedDheKeyLengthList;
    
    public void createClientHelloConfig(String type, String version) {
        this.type = type;
        this.version = version;
        this.config = null;
        this.trace = null;
        this.supportedRsaKeyLengthList = null;
        this.supportedDheKeyLengthList = null;
    }
    
    public String getType() {
        return type;
    }

    public String getVersion() {
        return version;
    }

    public void setConfig(Config config) {
        this.config = config;
    }
    
    public Config getConfig() {
        return config;
    }
    
    public void setTrace(WorkflowTrace trace) {
        this.trace = trace;
    }
    
    public WorkflowTrace getTrace() {
        return trace;
    }

    public void setSupportedRsaKeyLengthList(List<Integer> supportedRsaKeyLengthList) {
        this.supportedRsaKeyLengthList = supportedRsaKeyLengthList;
    }

    public List<Integer> getSupportedRsaKeyLengthList() {
        return supportedRsaKeyLengthList;
    }

    public void setSupportedDheKeyLengthList(List<Integer> supportedDheKeyLengthList) {
        this.supportedDheKeyLengthList = supportedDheKeyLengthList;
    }

    public List<Integer> getSupportedDheKeyLengthList() {
        return supportedDheKeyLengthList;
    }
}
