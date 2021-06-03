/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.model;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsscanner.serverscanner.guideline.model.extensions.GuidelineExtension;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlType;
import java.util.List;

@XmlType(propOrder = { "versions", "checks", "extensions", "cipherSuites", "namedGroups", "signatureAndHashAlgorithms",
    "signatureAndHashAlgorithmsCert", "signatureAlgorithms", "hashAlgorithms" })
public class GuidelineForVersion {

    private List<ProtocolVersion> versions;

    private List<GuidelineCheck> checks;
    private List<GuidelineExtension> extensions;
    private List<CipherSuite> cipherSuites;
    private List<NamedGroup> namedGroups;
    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;
    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmsCert;
    private List<SignatureAlgorithm> signatureAlgorithms;
    private List<HashAlgorithm> hashAlgorithms;

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    @XmlElement(name = "version")
    @XmlElementWrapper(name = "versions")
    public void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
    }

    public List<GuidelineCheck> getChecks() {
        return checks;
    }

    @XmlElement(name = "check")
    @XmlElementWrapper(name = "checks")
    public void setChecks(List<GuidelineCheck> checks) {
        this.checks = checks;
    }

    public List<GuidelineExtension> getExtensions() {
        return extensions;
    }

    @XmlElement(name = "extension")
    @XmlElementWrapper(name = "extensions")
    public void setExtensions(List<GuidelineExtension> extensions) {
        this.extensions = extensions;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    @XmlElement(name = "cipherSuite")
    @XmlElementWrapper(name = "cipherSuites")
    public void setCipherSuites(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public List<NamedGroup> getNamedGroups() {
        return namedGroups;
    }

    @XmlElement(name = "namedGroup")
    @XmlElementWrapper(name = "namedGroups")
    public void setNamedGroups(List<NamedGroup> namedGroups) {
        this.namedGroups = namedGroups;
    }

    public List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms() {
        return signatureAndHashAlgorithms;
    }

    @XmlElement(name = "signatureAndHashAlgorithm")
    @XmlElementWrapper(name = "signatureAndHashAlgorithms")
    public void setSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
        this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithmsCert() {
        return signatureAndHashAlgorithmsCert;
    }

    @XmlElement(name = "signatureAndHashAlgorithm")
    @XmlElementWrapper(name = "signatureAndHashAlgorithmsCert")
    public void setSignatureAndHashAlgorithmsCert(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmsCert) {
        this.signatureAndHashAlgorithmsCert = signatureAndHashAlgorithmsCert;
    }

    public List<SignatureAlgorithm> getSignatureAlgorithms() {
        return signatureAlgorithms;
    }

    @XmlElement(name = "signatureAlgorithm")
    @XmlElementWrapper(name = "signatureAlgorithms")
    public void setSignatureAlgorithms(List<SignatureAlgorithm> signatureAlgorithms) {
        this.signatureAlgorithms = signatureAlgorithms;
    }

    public List<HashAlgorithm> getHashAlgorithms() {
        return hashAlgorithms;
    }

    @XmlElement(name = "hashAlgorithm")
    @XmlElementWrapper(name = "hashAlgorithms")
    public void setHashAlgorithms(List<HashAlgorithm> hashAlgorithms) {
        this.hashAlgorithms = hashAlgorithms;
    }
}
