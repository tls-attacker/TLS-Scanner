/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.report;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.report.container.ReportContainer;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

@XmlRootElement()
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientReport extends TlsScanReport {

    // Ciphers
    private List<CipherSuite> clientAdvertisedCipherSuites;

    // Compression
    private List<CompressionMethod> clientAdvertisedCompressions;

    // DHE
    private Integer lowestPossibleDheModulusSize;
    private Integer highestPossibleDheModulusSize;

    // Extensions
    private Set<ExtensionType> clientAdvertisedExtensions;
    private List<SignatureAndHashAlgorithm> clientAdvertisedSignatureAndHashAlgorithms;
    private List<NamedGroup> clientAdvertisedNamedGroupsList;
    private List<NamedGroup> clientAdvertisedKeyShareNamedGroupsList;
    private List<ECPointFormat> clientAdvertisedPointFormatsList;
    private List<String> clientAdvertisedAlpns;

    public ClientReport() {
        super();
    }

    public synchronized List<CompressionMethod> getClientAdvertisedCompressions() {
        return clientAdvertisedCompressions;
    }

    public synchronized void setClientAdvertisedCompressions(
            List<CompressionMethod> clientAdvertisedCompressions) {
        this.clientAdvertisedCompressions = clientAdvertisedCompressions;
    }

    public synchronized List<SignatureAndHashAlgorithm>
            getClientAdvertisedSignatureAndHashAlgorithms() {
        return clientAdvertisedSignatureAndHashAlgorithms;
    }

    public synchronized void setClientAdvertisedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> clientAdvertisedSignatureAndHashAlgorithms) {
        this.clientAdvertisedSignatureAndHashAlgorithms =
                clientAdvertisedSignatureAndHashAlgorithms;
    }

    public synchronized Set<ExtensionType> getClientAdvertisedExtensions() {
        return clientAdvertisedExtensions;
    }

    public synchronized void setClientAdvertisedExtensions(
            Set<ExtensionType> clientAdvertisedExtensions) {
        this.clientAdvertisedExtensions = clientAdvertisedExtensions;
    }

    public synchronized List<NamedGroup> getClientAdvertisedNamedGroupsList() {
        return clientAdvertisedNamedGroupsList;
    }

    public synchronized void setClientAdvertisedNamedGroupsList(
            List<NamedGroup> clientAdvertisedNamedGroupsList) {
        this.clientAdvertisedNamedGroupsList = clientAdvertisedNamedGroupsList;
    }

    public synchronized List<ECPointFormat> getClientAdvertisedPointFormatsList() {
        return clientAdvertisedPointFormatsList;
    }

    public synchronized void setClientAdvertisedPointFormatsList(
            List<ECPointFormat> clientAdvertisedPointFormatsList) {
        this.clientAdvertisedPointFormatsList = clientAdvertisedPointFormatsList;
    }

    public synchronized Integer getLowestPossibleDheModulusSize() {
        return lowestPossibleDheModulusSize;
    }

    public Integer getHighestPossibleDheModulusSize() {
        return highestPossibleDheModulusSize;
    }

    public void setHighestPossibleDheModulusSize(Integer highestPossibleDheModulusSize) {
        this.highestPossibleDheModulusSize = highestPossibleDheModulusSize;
    }

    public synchronized void setLowestPossibleDheModulusSize(Integer lowestPossibleDheModulusSize) {
        this.lowestPossibleDheModulusSize = lowestPossibleDheModulusSize;
    }

    public synchronized List<CipherSuite> getClientAdvertisedCipherSuites() {
        return clientAdvertisedCipherSuites;
    }

    public synchronized void setClientAdvertisedCipherSuites(
            List<CipherSuite> clientAdvertisedCipherSuites) {
        this.clientAdvertisedCipherSuites = clientAdvertisedCipherSuites;
    }

    public synchronized void addClientAdvertisedCipherSuites(
            List<CipherSuite> clientAdvertisedCipherSuites) {
        if (this.clientAdvertisedCipherSuites == null) {
            this.clientAdvertisedCipherSuites = new LinkedList<>();
        }
        this.clientAdvertisedCipherSuites.addAll(clientAdvertisedCipherSuites);
    }

    public synchronized List<NamedGroup> getClientAdvertisedKeyShareNamedGroupsList() {
        return clientAdvertisedKeyShareNamedGroupsList;
    }

    public synchronized void setClientAdvertisedKeyShareNamedGroupsList(
            List<NamedGroup> clientAdvertisedKeyShareNamedGroupsList) {
        this.clientAdvertisedKeyShareNamedGroupsList = clientAdvertisedKeyShareNamedGroupsList;
    }

    public synchronized List<String> getClientAdvertisedAlpns() {
        return clientAdvertisedAlpns;
    }

    public synchronized void setClientAdvertisedAlpns(List<String> clientAdvertisedAlpns) {
        this.clientAdvertisedAlpns = clientAdvertisedAlpns;
    }

    @Override
    public String getFullReport(ScannerDetail detail, boolean printColorful) {
        // TODO: Implement ClientReportPrinter and use them.
        ClientContainerReportCreator creator = new ClientContainerReportCreator(detail);
        ReportContainer createReport = creator.createReport(this);
        StringBuilder builder = new StringBuilder();
        createReport.print(builder, 0, printColorful);
        return builder.toString();
    }

    @Override
    public synchronized String toString() {
        return getFullReport(ScannerDetail.NORMAL, false);
    }
}
