/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.report;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.CompositeModulusResult;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.SmallSubgroupResult;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.report.container.ReportContainer;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import java.util.List;
import java.util.Set;

@XmlRootElement()
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientReport extends ScanReport {

    private List<VersionSuiteListPair> versionSuitePairs;
    private List<ProtocolVersion> supportedVersions;
    private List<CipherSuite> advertisedCipherSuites;

    private List<SmallSubgroupResult> smallDheSubgroupResults;
    private List<CompositeModulusResult> compositeDheModulusResultList;

    private List<CompressionMethod> clientAdvertisedCompressions;
    private List<SignatureAndHashAlgorithm> clientAdvertisedSignatureAndHashAlgorithms;
    private Set<ExtensionType> clientAdvertisedExtensions;
    private List<NamedGroup> clientAdvertisedNamedGroupsList;
    private List<NamedGroup> clientAdvertisedKeyShareNamedGroupsList;
    private List<ECPointFormat> clientAdvertisedPointFormatsList;

    private Integer lowestPossibleDheModulusSize;

    public ClientReport() {
        super();
    }

    public synchronized List<CompressionMethod> getClientAdvertisedCompressions() {
        return clientAdvertisedCompressions;
    }

    public synchronized void setClientAdvertisedCompressions(List<CompressionMethod> clientAdvertisedCompressions) {
        this.clientAdvertisedCompressions = clientAdvertisedCompressions;
    }

    public synchronized List<SignatureAndHashAlgorithm> getClientAdvertisedSignatureAndHashAlgorithms() {
        return clientAdvertisedSignatureAndHashAlgorithms;
    }

    public synchronized void setClientAdvertisedSignatureAndHashAlgorithms(
        List<SignatureAndHashAlgorithm> clientAdvertisedSignatureAndHashAlgorithms) {
        this.clientAdvertisedSignatureAndHashAlgorithms = clientAdvertisedSignatureAndHashAlgorithms;
    }

    public synchronized Set<ExtensionType> getClientAdvertisedExtensions() {
        return clientAdvertisedExtensions;
    }

    public synchronized void setClientAdvertisedExtensions(Set<ExtensionType> clientAdvertisedExtensions) {
        this.clientAdvertisedExtensions = clientAdvertisedExtensions;
    }

    public synchronized List<NamedGroup> getClientAdvertisedNamedGroupsList() {
        return clientAdvertisedNamedGroupsList;
    }

    public synchronized void setClientAdvertisedNamedGroupsList(List<NamedGroup> clientAdvertisedNamedGroupsList) {
        this.clientAdvertisedNamedGroupsList = clientAdvertisedNamedGroupsList;
    }

    public synchronized List<ECPointFormat> getClientAdvertisedPointFormatsList() {
        return clientAdvertisedPointFormatsList;
    }

    public synchronized void setClientAdvertisedPointFormatsList(List<ECPointFormat> clientAdvertisedPointFormatsList) {
        this.clientAdvertisedPointFormatsList = clientAdvertisedPointFormatsList;
    }

    public synchronized Integer getLowestPossibleDheModulusSize() {
        return lowestPossibleDheModulusSize;
    }

    public synchronized void setLowestPossibleDheModulusSize(Integer lowestPossibleDheModulusSize) {
        this.lowestPossibleDheModulusSize = lowestPossibleDheModulusSize;
    }

    public synchronized List<SmallSubgroupResult> getSmallDheSubgroupResults() {
        return smallDheSubgroupResults;
    }

    public synchronized void setSmallDheSubgroupResults(List<SmallSubgroupResult> smallDheSubgroupResults) {
        this.smallDheSubgroupResults = smallDheSubgroupResults;
    }

    public synchronized List<CompositeModulusResult> getCompositeDheModulusResultList() {
        return compositeDheModulusResultList;
    }

    public synchronized void
        setCompositeDheModulusResultList(List<CompositeModulusResult> compositeDheModulusResultList) {
        this.compositeDheModulusResultList = compositeDheModulusResultList;
    }

    public synchronized List<ProtocolVersion> getSupportedVersions() {
        return supportedVersions;
    }

    public synchronized void setSupportedVersions(List<ProtocolVersion> supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    public synchronized List<VersionSuiteListPair> getVersionSuitePairs() {
        return versionSuitePairs;
    }

    public synchronized void setVersionSuitePairs(List<VersionSuiteListPair> versionSuitePairs) {
        this.versionSuitePairs = versionSuitePairs;
    }

    public synchronized List<CipherSuite> getAdvertisedCipherSuites() {
        return advertisedCipherSuites;
    }

    public synchronized void setAdvertisedCipherSuites(List<CipherSuite> advertisedCipherSuites) {
        this.advertisedCipherSuites = advertisedCipherSuites;
    }

    @Override
    public String getFullReport(ScannerDetail detail, boolean printColorful) {
        ClientContainerReportCreator creator = new ClientContainerReportCreator();
        ReportContainer createReport = creator.createReport(this);
        StringBuilder builder = new StringBuilder();
        createReport.print(builder, 0, printColorful);
        return builder.toString();
    }

    public synchronized List<NamedGroup> getClientAdvertisedKeyShareNamedGroupsList() {
        return clientAdvertisedKeyShareNamedGroupsList;
    }

    public synchronized void
        setClientAdvertisedKeyShareNamedGroupsList(List<NamedGroup> clientAdvertisedKeyShareNamedGroupsList) {
        this.clientAdvertisedKeyShareNamedGroupsList = clientAdvertisedKeyShareNamedGroupsList;
    }
}
