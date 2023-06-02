/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.report;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.report.container.ReportContainer;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Set;

@XmlRootElement()
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientReport extends TlsScanReport {

    // DHE
    private Integer lowestPossibleDheModulusSize;
    private Integer highestPossibleDheModulusSize;

    private Integer minimumServerCertificateKeySizeDH = -1;
    private Integer minimumServerCertificateKeySizeRSA = -1;
    private Integer minimumServerCertificateKeySizeDSS = -1;

    public ClientReport() {
        super();
    }

    public synchronized List<CompressionMethod> getClientAdvertisedCompressions() {
        @SuppressWarnings("unchecked")
        ListResult<CompressionMethod> listResult =
                (ListResult<CompressionMethod>)
                        getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_COMPRESSIONS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<SignatureAndHashAlgorithm>
            getClientAdvertisedSignatureAndHashAlgorithms() {
        @SuppressWarnings("unchecked")
        ListResult<SignatureAndHashAlgorithm> listResult =
                (ListResult<SignatureAndHashAlgorithm>)
                        getListResult(
                                TlsAnalyzedProperty
                                        .CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized Set<ExtensionType> getClientAdvertisedExtensions() {
        @SuppressWarnings("unchecked")
        SetResult<ExtensionType> setResult =
                (SetResult<ExtensionType>)
                        getSetResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS);
        return setResult == null ? null : setResult.getSet();
    }

    public synchronized List<NamedGroup> getClientAdvertisedNamedGroupsList() {
        @SuppressWarnings("unchecked")
        ListResult<NamedGroup> listResult =
                (ListResult<NamedGroup>)
                        getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_NAMED_GROUPS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<ECPointFormat> getClientAdvertisedPointFormatsList() {
        @SuppressWarnings("unchecked")
        ListResult<ECPointFormat> listResult =
                (ListResult<ECPointFormat>)
                        getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_POINTFORMATS);
        return listResult == null ? null : listResult.getList();
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
        @SuppressWarnings("unchecked")
        ListResult<CipherSuite> listResult =
                (ListResult<CipherSuite>)
                        getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_CIPHERSUITES);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized void addClientAdvertisedCipherSuites(
            List<CipherSuite> clientAdvertisedCipherSuites) {
        getClientAdvertisedCipherSuites().addAll(clientAdvertisedCipherSuites);
    }

    public synchronized List<NamedGroup> getClientAdvertisedKeyShareNamedGroupsList() {
        @SuppressWarnings("unchecked")
        ListResult<NamedGroup> listResult =
                (ListResult<NamedGroup>)
                        getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_KEYSHARE_NAMED_GROUPS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<String> getClientAdvertisedAlpns() {
        @SuppressWarnings("unchecked")
        ListResult<String> listResult =
                (ListResult<String>) getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_ALPNS);
        return listResult == null ? null : listResult.getList();
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

    public synchronized Integer getMinimumServerCertificateKeySizeDH() {
        return minimumServerCertificateKeySizeDH;
    }

    public synchronized void setMinimumServerCertificateKeySizeDH(
            Integer minimumServerCertificateKeySizeDH) {
        this.minimumServerCertificateKeySizeDH = minimumServerCertificateKeySizeDH;
    }

    public synchronized Integer getMinimumServerCertificateKeySizeRSA() {
        return minimumServerCertificateKeySizeRSA;
    }

    public synchronized void setMinimumServerCertificateKeySizeRSA(
            Integer minimumServerCertificateKeySizeRSA) {
        this.minimumServerCertificateKeySizeRSA = minimumServerCertificateKeySizeRSA;
    }

    public synchronized Integer getMinimumServerCertificateKeySizeDSS() {
        return minimumServerCertificateKeySizeDSS;
    }

    public synchronized void setMinimumServerCertificateKeySizeDSS(
            Integer minimumServerCertificateKeySizeDSS) {
        this.minimumServerCertificateKeySizeDSS = minimumServerCertificateKeySizeDSS;
    }
}
