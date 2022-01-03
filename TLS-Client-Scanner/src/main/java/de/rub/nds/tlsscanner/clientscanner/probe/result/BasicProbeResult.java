/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.List;
import java.util.Set;

public class BasicProbeResult extends ProbeResult<ClientReport> {

    private final List<CipherSuite> clientAdvertisedCipherSuites;
    private final List<CompressionMethod> clientAdvertisedCompressions;
    private final List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms;
    private final Set<ExtensionType> clientAdvertisedExtensions;
    private final List<NamedGroup> clientAdvertisedNamedGroupsList;
    private final List<NamedGroup> clientKeyShareNamedGroupsList;
    private final List<ECPointFormat> clientAdvertisedPointFormatsList;

    public BasicProbeResult(List<CipherSuite> clientSupportedCipherSuites,
        List<CompressionMethod> clientSupportedCompressions,
        List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms,
        Set<ExtensionType> clientAdvertisedExtensions, List<NamedGroup> clientAdvertisedNamedGroupsList,
        List<NamedGroup> clientKeyShareNamedGroupsList, List<ECPointFormat> clientAdvertisedPointFormatsList) {
        super(TlsProbeType.BASIC);
        this.clientAdvertisedCipherSuites = clientSupportedCipherSuites;
        this.clientAdvertisedCompressions = clientSupportedCompressions;
        this.clientSupportedSignatureAndHashAlgorithms = clientSupportedSignatureAndHashAlgorithms;
        this.clientAdvertisedExtensions = clientAdvertisedExtensions;
        this.clientAdvertisedNamedGroupsList = clientAdvertisedNamedGroupsList;
        this.clientAdvertisedPointFormatsList = clientAdvertisedPointFormatsList;
        this.clientKeyShareNamedGroupsList = clientKeyShareNamedGroupsList;
    }

    @Override
    protected void mergeData(ClientReport report) {
        report.setAdvertisedCipherSuites(clientAdvertisedCipherSuites);
        report.setClientAdvertisedCompressions(clientAdvertisedCompressions);
        report.setClientAdvertisedSignatureAndHashAlgorithms(clientSupportedSignatureAndHashAlgorithms);
        report.setClientAdvertisedExtensions(clientAdvertisedExtensions);
        report.setClientAdvertisedNamedGroupsList(clientAdvertisedNamedGroupsList);
        report.setClientAdvertisedKeyShareNamedGroupsList(clientKeyShareNamedGroupsList);
        report.setClientAdvertisedPointFormatsList(clientAdvertisedPointFormatsList);
    }

}
