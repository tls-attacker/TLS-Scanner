/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.samples;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlscrawler.utility.ITuple;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author robert
 */
public class CsvReport {

    private CipherSuite suite;

    private ProtocolVersion version;

    private boolean vulnerable;

    private boolean shaky;

    private boolean scanError;

    private List<String> responseMap;

    public CsvReport(CipherSuite suite, ProtocolVersion version, boolean vulnerable, boolean shaky, boolean scanError, List<String> responseMap) {
        this.suite = suite;
        this.version = version;
        this.vulnerable = vulnerable;
        this.shaky = shaky;
        this.scanError = scanError;
        this.responseMap = new LinkedList<>();
        for (String s : responseMap) {
            this.responseMap.add(s);
        }
    }

    public CsvReport(CsvReport report) {
        this.suite = report.getSuite();
        this.version = report.getVersion();
        this.vulnerable = report.isVulnerable();
        this.shaky = report.isShaky();
        this.scanError = report.isScanError();
        this.responseMap = new ArrayList<>(report.getResponseMap());
    }

    public List<String> getResponseMap() {
        return responseMap;
    }

    public CipherSuite getSuite() {
        return suite;
    }

    public void setSuite(CipherSuite suite) {
        this.suite = suite;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public void setVersion(ProtocolVersion version) {
        this.version = version;
    }

    public boolean isVulnerable() {
        return vulnerable;
    }

    public void setVulnerable(boolean vulnerable) {
        this.vulnerable = vulnerable;
    }

    public boolean isShaky() {
        return shaky;
    }

    public void setShaky(boolean shaky) {
        this.shaky = shaky;
    }

    public boolean isScanError() {
        return scanError;
    }

    public void setScanError(boolean scanError) {
        this.scanError = scanError;
    }

    public boolean softEquals(CsvReport reportTwo) {
        if (reportTwo.getResponseMap().size() != this.responseMap.size()) {
            return false;
        }
        for (int i = 0; i < reportTwo.getResponseMap().size(); i++) {
            if (!responseMap.get(i).split("paddingVector")[0].equals(responseMap.get(i).split("paddingVector")[0])) {
                return false;
            }
        }
        return true;
    }

    public boolean vulnMapLooksSimilar(List<String> vulnMap) {
        int size;
        if (vulnMap.size() < this.responseMap.size()) {
            size = vulnMap.size();
        } else {
            size = responseMap.size();
        }
        for (int i = 0; i < size; i++) {
            if (!responseMap.get(i).split("paddingVector")[0].equals(vulnMap.get(i).split("paddingVector")[0])) {
                return false;
            }
        }
        return true;
    }

    public String toCsvString() {
        StringBuilder builder = new StringBuilder();
        builder.append("version,").append(suite.name()).append(",").append(version).append(",");
        for (String someString : responseMap) {
            builder.append(someString);
            builder.append(",");
        }
        return builder.toString();
    }
}
