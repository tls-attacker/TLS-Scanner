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

    private List<CipherSuite> clientAdvertisedCipherSuites;
    private List<CompressionMethod> clientAdvertisedCompressions;
    private List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms;
    private Set<ExtensionType> clientAdvertisedExtensions;
    private List<NamedGroup> clientAdvertisedNamedGroupsList;
    private List<NamedGroup> clientKeyShareNamedGroupsList;
    private List<ECPointFormat> clientAdvertisedPointFormatsList;
    
    @Override
    public String name() {
        return "BasicProbeTestResult";
    }

	/**
	 * @return the clientAdvertisedCipherSuites
	 */
	public List<CipherSuite> getClientAdvertisedCipherSuites() {
		return clientAdvertisedCipherSuites;
	}

	/**
	 * @param clientAdvertisedCipherSuites the clientAdvertisedCipherSuites to set
	 */
	public void setClientAdvertisedCipherSuites(List<CipherSuite> clientAdvertisedCipherSuites) {
		this.clientAdvertisedCipherSuites = clientAdvertisedCipherSuites;
	}

	/**
	 * @return the clientAdvertisedCompressions
	 */
	public List<CompressionMethod> getClientAdvertisedCompressions() {
		return clientAdvertisedCompressions;
	}

	/**
	 * @param clientAdvertisedCompressions the clientAdvertisedCompressions to set
	 */
	public void setClientAdvertisedCompressions(List<CompressionMethod> clientAdvertisedCompressions) {
		this.clientAdvertisedCompressions = clientAdvertisedCompressions;
	}

	/**
	 * @return the clientSupportedSignatureAndHashAlgorithms
	 */
	public List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms() {
		return clientSupportedSignatureAndHashAlgorithms;
	}

	/**
	 * @param clientSupportedSignatureAndHashAlgorithms the clientSupportedSignatureAndHashAlgorithms to set
	 */
	public void setClientSupportedSignatureAndHashAlgorithms(
			List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms) {
		this.clientSupportedSignatureAndHashAlgorithms = clientSupportedSignatureAndHashAlgorithms;
	}

	/**
	 * @return the clientAdvertisedExtensions
	 */
	public Set<ExtensionType> getClientAdvertisedExtensions() {
		return clientAdvertisedExtensions;
	}

	/**
	 * @param clientAdvertisedExtensions the clientAdvertisedExtensions to set
	 */
	public void setClientAdvertisedExtensions(Set<ExtensionType> clientAdvertisedExtensions) {
		this.clientAdvertisedExtensions = clientAdvertisedExtensions;
	}

	/**
	 * @return the clientAdvertisedNamedGroupsList
	 */
	public List<NamedGroup> getClientAdvertisedNamedGroupsList() {
		return clientAdvertisedNamedGroupsList;
	}

	/**
	 * @param clientAdvertisedNamedGroupsList the clientAdvertisedNamedGroupsList to set
	 */
	public void setClientAdvertisedNamedGroupsList(List<NamedGroup> clientAdvertisedNamedGroupsList) {
		this.clientAdvertisedNamedGroupsList = clientAdvertisedNamedGroupsList;
	}

	/**
	 * @return the clientKeyShareNamedGroupsList
	 */
	public List<NamedGroup> getClientKeyShareNamedGroupsList() {
		return clientKeyShareNamedGroupsList;
	}

	/**
	 * @param clientKeyShareNamedGroupsList the clientKeyShareNamedGroupsList to set
	 */
	public void setClientKeyShareNamedGroupsList(List<NamedGroup> clientKeyShareNamedGroupsList) {
		this.clientKeyShareNamedGroupsList = clientKeyShareNamedGroupsList;
	}

	/**
	 * @return the clientAdvertisedPointFormatsList
	 */
	public List<ECPointFormat> getClientAdvertisedPointFormatsList() {
		return clientAdvertisedPointFormatsList;
	}

	/**
	 * @param clientAdvertisedPointFormatsList the clientAdvertisedPointFormatsList to set
	 */
	public void setClientAdvertisedPointFormatsList(List<ECPointFormat> clientAdvertisedPointFormatsList) {
		this.clientAdvertisedPointFormatsList = clientAdvertisedPointFormatsList;
	}

}
