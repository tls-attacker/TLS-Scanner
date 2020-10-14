package de.rub.nds.tlsscanner.clientscanner.config;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;

import com.beust.jcommander.Parameter;

import org.bouncycastle.crypto.tls.Certificate;

import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.certificate.PemUtil;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class CACertDelegate extends Delegate {
    @Parameter(names = "-ca_cert", description = "PEM encoded certificate file")
    private String certPath = null;

    @Parameter(names = "-ca_key", description = "PEM encoded private key")
    private String keyPath = null;

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        try {
            Certificate cert = PemUtil.readCertificate(new File(certPath));
            PrivateKey privateKey = PemUtil.readPrivateKey(new File(keyPath));
            config.setDefaultExplicitCertificateKeyPair(new CertificateKeyPair(cert, privateKey));
            config.setAutoSelectCertificate(false);
        } catch (CertificateException | IOException e) {
            throw new ConfigurationException("Failed to set Certificate and key", e);
        }
    }

}
