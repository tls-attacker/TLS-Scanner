/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlType(propOrder={"result", "information", "handlingRecommendation", "additionalInformation", "links"})
public class PropertyRecommendation {
    
    private TestResult result;
    
    private String information;
    
    private String handlingRecommendation;
    
    private String additionalInformation;
    
    private List<String> links;
    
    public PropertyRecommendation() {
        links = new LinkedList<>();
    }
    
    public PropertyRecommendation(TestResult result, String resultStatus, String handlingRecommendation, 
            String additionInformation, List<String> links) {
        this.result = result;
        this.information = resultStatus;
        this.handlingRecommendation = handlingRecommendation;
        this.additionalInformation = additionInformation;
        this.links = links;
    }
    
    public PropertyRecommendation(TestResult result, String resultStatus, String handlingRecommendation) {
        this.result = result;
        this.information = resultStatus;
        this.handlingRecommendation = handlingRecommendation;
    }

    public TestResult getResult() {
        return result;
    }

    public void setResult(TestResult result) {
        this.result = result;
    }

    public String getInformation() {
        return information;
    }

    public void setInformation(String information) {
        this.information = information;
    }

    public String getHandlingRecommendation() {
        return handlingRecommendation;
    }

    public void setHandlingRecommendation(String handlingRecommendation) {
        this.handlingRecommendation = handlingRecommendation;
    }

    public String getAdditionalInformation() {
        return additionalInformation;
    }

    public void setAdditionalInformation(String additionalInformation) {
        this.additionalInformation = additionalInformation;
    }

    @XmlElement(name = "link")
    public List<String> getLinks() {
        return links;
    }

    public void setLinks(List<String> links) {
        this.links = links;
    }
}
