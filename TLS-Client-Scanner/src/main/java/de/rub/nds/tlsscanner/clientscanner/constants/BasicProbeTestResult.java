/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.constants;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.util.List;
import java.util.Set;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "result")
@XmlAccessorType(XmlAccessType.FIELD)
public class BasicProbeTestResult implements TestResult {

    private final List<CipherSuite> clientAdvertisedCipherSuites;
    private final List<CompressionMethod> clientAdvertisedCompressions;
    private final List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms;
    private final Set<ExtensionType> clientAdvertisedExtensions;
    private final List<NamedGroup> clientAdvertisedNamedGroupsList;
    private final List<NamedGroup> clientKeyShareNamedGroupsList;
    private final List<ECPointFormat> clientAdvertisedPointFormatsList;

    @Override
    public String name() {
        return "BasicProbeTestResult";
    }

    public BasicProbeTestResult(List<CipherSuite> clientAdvertisedCipherSuites,
        List<CompressionMethod> clientAdvertisedCompressions,
        List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms,
        Set<ExtensionType> clientAdvertisedExtensions, List<NamedGroup> clientAdvertisedNamedGroupsList,
        List<NamedGroup> clientKeyShareNamedGroupsList, List<ECPointFormat> clientAdvertisedPointFormatsList) {
        this.clientAdvertisedCipherSuites = clientAdvertisedCipherSuites;
        this.clientAdvertisedCompressions = clientAdvertisedCompressions;
        this.clientSupportedSignatureAndHashAlgorithms = clientSupportedSignatureAndHashAlgorithms;
        this.clientAdvertisedExtensions = clientAdvertisedExtensions;
        this.clientAdvertisedNamedGroupsList = clientAdvertisedNamedGroupsList;
        this.clientKeyShareNamedGroupsList = clientKeyShareNamedGroupsList;
        this.clientAdvertisedPointFormatsList = clientAdvertisedPointFormatsList;
    }

    /**
     * @return the clientAdvertisedCipherSuites
     */
    public List<CipherSuite> getClientAdvertisedCipherSuites() {
        return clientAdvertisedCipherSuites;
    }

    /**
     * @return the clientAdvertisedCompressions
     */
    public List<CompressionMethod> getClientAdvertisedCompressions() {
        return clientAdvertisedCompressions;
    }

    /**
     * @return the clientSupportedSignatureAndHashAlgorithms
     */
    public List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms() {
        return clientSupportedSignatureAndHashAlgorithms;
    }

    /**
     * @return the clientAdvertisedExtensions
     */
    public Set<ExtensionType> getClientAdvertisedExtensions() {
        return clientAdvertisedExtensions;
    }

    /**
     * @return the clientAdvertisedNamedGroupsList
     */
    public List<NamedGroup> getClientAdvertisedNamedGroupsList() {
        return clientAdvertisedNamedGroupsList;
    }

    /**
     * @return the clientKeyShareNamedGroupsList
     */
    public List<NamedGroup> getClientKeyShareNamedGroupsList() {
        return clientKeyShareNamedGroupsList;
    }

    /**
     * @return the clientAdvertisedPointFormatsList
     */
    public List<ECPointFormat> getClientAdvertisedPointFormatsList() {
        return clientAdvertisedPointFormatsList;
    }
}
