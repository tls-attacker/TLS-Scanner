/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.io.Serializable;
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
    private Integer rsaMin;
    private Integer rsaMax;
    private Integer dhMin;
    private Integer dhMax;
    
    public void createClientHelloConfig(String type, String version) {
        this.type = type;
        this.version = version;
        this.config = null;
        this.trace = null;
        this.rsaMin = null;
        this.rsaMax = null;
        this.dhMin = null;
        this.dhMax = null;
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

    public void setRsaMin(Integer rsaMin) {
        this.rsaMin = rsaMin;
    }

    public Integer getRsaMin() {
        return rsaMin;
    }

    public void setRsaMax(Integer rsaMax) {
        this.rsaMax = rsaMax;
    }

    public Integer getRsaMax() {
        return rsaMax;
    }

    public void setDhMin(Integer dhMin) {
        this.dhMin = dhMin;
    }

    public Integer getDhMin() {
        return dhMin;
    }

    public void setDhMax(Integer dhMax) {
        this.dhMax = dhMax;
    }

    public Integer getDhMax() {
        return dhMax;
    }
}
