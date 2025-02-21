/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.report;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ByteArraySerializer;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.SetResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.converter.PointSerializer;
import de.rub.nds.tlsscanner.core.converter.ResponseFingerprintSerializer;
import de.rub.nds.tlsscanner.core.converter.VectorSerializer;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.OutputStream;
import java.util.List;
import java.util.Set;

@XmlRootElement()
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientReport extends TlsScanReport {

    public static Module[] getSerializerModules() {
        return new Module[] {
            new SimpleModule()
                    .addSerializer(new ByteArraySerializer())
                    .addSerializer(new ResponseFingerprintSerializer())
                    .addSerializer(new VectorSerializer())
                    .addSerializer(new PointSerializer()),
            new JodaModule()
        };
    }

    public ClientReport() {
        super();
    }

    @Override
    public void serializeToJson(OutputStream outputStream) {
        ClientReportSerializer.serialize(outputStream, this);
    }

    public synchronized List<CompressionMethod> getClientAdvertisedCompressions() {
        ListResult<CompressionMethod> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_COMPRESSIONS,
                        CompressionMethod.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<SignatureAndHashAlgorithm>
            getClientAdvertisedSignatureAndHashAlgorithms() {
        ListResult<SignatureAndHashAlgorithm> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                        SignatureAndHashAlgorithm.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized Set<ExtensionType> getClientAdvertisedExtensions() {
        SetResult<ExtensionType> setResult =
                getSetResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS, ExtensionType.class);
        return setResult == null ? null : setResult.getSet();
    }

    public synchronized List<NamedGroup> getClientAdvertisedNamedGroupsList() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_NAMED_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<ECPointFormat> getClientAdvertisedPointFormatsList() {
        ListResult<ECPointFormat> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_POINTFORMATS, ECPointFormat.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<CipherSuite> getClientAdvertisedCipherSuites() {
        ListResult<CipherSuite> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_CIPHERSUITES, CipherSuite.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized void addClientAdvertisedCipherSuites(
            List<CipherSuite> clientAdvertisedCipherSuites) {
        getClientAdvertisedCipherSuites().addAll(clientAdvertisedCipherSuites);
    }

    public synchronized List<NamedGroup> getClientAdvertisedKeyShareNamedGroupsList() {
        ListResult<NamedGroup> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_KEYSHARE_NAMED_GROUPS,
                        NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<String> getClientAdvertisedAlpns() {
        @SuppressWarnings("unchecked")
        ListResult<String> listResult =
                (ListResult<String>) getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_ALPNS);
        return listResult == null ? null : listResult.getList();
    }
}
