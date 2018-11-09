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
        for (CsvReport reportOne : vulnerabilityList) {
            for (CsvReport reportTwo : vulnerabilityList) {
                if (reportOne.getSuite() == reportTwo.getSuite() && reportOne.getVersion() == reportTwo.getVersion()) {
                    if (reportOne.softEquals(reportTwo)) {
                        return true;
                    } else {
                        return false;
                    }
                }
            }
        }
        return false;
    }

    public boolean contradicts(Report otherReport) {
        for (CsvReport csv : vulnerabilityList) {
            for (CsvReport otherCsv : otherReport.getVulnerabilityList()) {
                if (otherCsv.getSuite() == csv.getSuite() && otherCsv.getVersion() == csv.getVersion()) {
                    if (csv.isScanError() || csv.isScanError() || otherCsv.isShaky() || otherCsv.isScanError()) {
                        continue;
                    }
                    if (csv.isVulnerable() != otherCsv.isVulnerable()) {
                        return true;
                    }
                    if (!otherCsv.vulnMapLooksSimilar(csv.getResponseMap())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    public boolean softContradicts(Report otherReport) {
        for (CsvReport csv : vulnerabilityList) {
            for (CsvReport otherCsv : otherReport.getVulnerabilityList()) {
                if (otherCsv.getSuite() == csv.getSuite() && otherCsv.getVersion() == csv.getVersion()) {
                    if (csv.isScanError() || csv.isScanError() || otherCsv.isShaky() || otherCsv.isScanError()) {
                        continue;
                    }
                    if (csv.isVulnerable() != otherCsv.isVulnerable()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }


    public boolean vulnCsvAreEqual() {
        List<String> vulnerability = null;
        for (CsvReport report : vulnerabilityList) {
            if (report.isVulnerable() && !report.isShaky() && !report.isScanError()) {
                if (vulnerability == null) {
                    vulnerability = report.getResponseMap();
                } else {
                    if (!report.vulnMapLooksSimilar(vulnerability)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }
}
