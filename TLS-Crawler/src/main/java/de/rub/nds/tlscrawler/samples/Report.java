/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.samples;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author robert
 */
public class Report {

    private String host;

    private List<CsvReport> vulnerabilityList;

    public Report(String host) {
        this.host = host;
        this.vulnerabilityList = new LinkedList<>();
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public List<CsvReport> getVulnerabilityList() {
        return vulnerabilityList;
    }

    public void setVulnerabilityList(List<CsvReport> vulnerabilityList) {
        this.vulnerabilityList = vulnerabilityList;
    }

    public void addCsvReport(CsvReport report) {
        vulnerabilityList.add(report);
    }

    public Report(Report r) {
        this.host = r.host;
        this.vulnerabilityList = copyOf(r.vulnerabilityList);
    }

    private List<CsvReport> copyOf(List<CsvReport> vulnerabilityList) {
        List<CsvReport> linkedList = new LinkedList<>();
        for (CsvReport report : vulnerabilityList) {
            linkedList.add(new CsvReport(report));
        }
        return linkedList;
    }

    public boolean allAreVulnerable() {
        boolean vuln = true;
        for (CsvReport report : vulnerabilityList) {
            if (!report.isShaky() && !report.isScanError()) {
                vuln &= report.isVulnerable();
            } else {
                vuln = false;
            }
        }
        return vuln;
    }

    public boolean allVulnEqual(Report r) {
        CsvReport reportOne = vulnerabilityList.get(0);
        CsvReport reportTwo = r.getVulnerabilityList().get(0);
        if (reportOne.softEquals(reportTwo)) {
            return true;
        } else {
            return false;
        }
    }

}
