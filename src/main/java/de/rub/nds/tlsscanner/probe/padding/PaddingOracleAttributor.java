/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.padding;

import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class tries to attribute discovered padding oracles
 *
 * @author ic0ns
 */
public class PaddingOracleAttributor {

    private final Logger LOGGER = LogManager.getLogger();

    private final List<KnownPaddingOracleVulnerability> knownVulnerabilityList;

    public PaddingOracleAttributor() {
        knownVulnerabilityList = new LinkedList<>();
        knownVulnerabilityList.addAll(createCve20162107());
        knownVulnerabilityList.addAll(createCve20191559());
        knownVulnerabilityList.addAll(createCve20196485());
        knownVulnerabilityList.addAll(createCve20196593());
        knownVulnerabilityList.addAll(createUnpatchedOne());
        knownVulnerabilityList.addAll(createUnpatchedTwo());
        knownVulnerabilityList.addAll(createUnpatchedThree());
    }

    private List<KnownPaddingOracleVulnerability> createCve20196593() {
        List<KnownPaddingOracleVulnerability> knownVulnList = new LinkedList<>();
        List<CipherSuite> knownVulnableSuites = new LinkedList<>();
        List<CipherSuite> knownNotVulnableSuites = new LinkedList<>();

        List<String> affectedProducts = new LinkedList<>();
        affectedProducts
                .add("BIG-IP (LTM, AAM, AFM, Analytics, APM, ASM, DNS, Edge Gateway, FPS, GTM, Link Controller, PEM, WebAccelerator)");
        List<ProtocolMessage> messageList = new LinkedList<>();
        ResponseFingerprint responseOne = new ResponseFingerprint(false, false, 0, 0, null, null, messageList, null,
                SocketState.CLOSED);
        ResponseFingerprint responseTwo = new ResponseFingerprint(false, false, 0, 0, null, null, messageList, null,
                SocketState.TIMEOUT);

        List<IdentifierResponse> responseList = new LinkedList<>();
        responseList.add(new IdentifierResponse("BasicMac1", responseOne));
        responseList.add(new IdentifierResponse("BasicMac2", responseOne));
        responseList.add(new IdentifierResponse("BasicMac3", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteFirst", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteLast", responseOne));
        responseList.add(new IdentifierResponse("PlainOnlyPadding", responseOne));
        responseList.add(new IdentifierResponse("PlainTooMuchPadding", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadValMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd", responseTwo));

        responseList.add(new IdentifierResponse("ValPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd", responseTwo));

        String description = "On BIG-IP 11.5.1-11.5.4, 11.6.1, and 12.1.0, a virtual server configured with a Client SSL \n"
                + "profile may be vulnerable to a chosen ciphertext attack against CBC ciphers. When exploited, this may \n"
                + "result in plaintext recovery of encrypted messages through a man-in-the-middle (MITM) attack, despite the\n"
                + " attacker not having gained access to the server's private key itself. (CVE-2019-6593 also known as \n"
                + "Zombie POODLE and GOLDENDOODLE.)";
        knownVulnList.add(new KnownPaddingOracleVulnerability("CVE-2019-6593", "F5 BIG-IP CVE-2019-6593",
                "F5 BIG-IP virtual server CVE-2019-6593", PaddingOracleStrength.STRONG, true, knownVulnableSuites,
                knownNotVulnableSuites, description, affectedProducts, responseList, true));

        return knownVulnList;
    }

    private List<KnownPaddingOracleVulnerability> createUnpatchedOne() {
        List<KnownPaddingOracleVulnerability> knownVulnList = new LinkedList<>();
        List<CipherSuite> knownVulnableSuites = new LinkedList<>();
        knownVulnableSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);

        List<CipherSuite> knownNotVulnableSuites = new LinkedList<>();
        knownNotVulnableSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384);
        knownNotVulnableSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384);
        knownNotVulnableSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        knownNotVulnableSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);

        List<String> affectedProducts = new LinkedList<>();
        affectedProducts.add("- To be announced -");
        affectedProducts.add("- To be announced -");
        List<ProtocolMessage> messageList = new LinkedList<>();
        AlertMessage alert = new AlertMessage();
        alert.setDescription(AlertDescription.INTERNAL_ERROR.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        ResponseFingerprint responseOne = new ResponseFingerprint(false, true, 1, 1, null, null, messageList, null,
                SocketState.CLOSED);
        messageList = new LinkedList<>();
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.BAD_RECORD_MAC.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        ResponseFingerprint responseTwo = new ResponseFingerprint(false, true, 1, 1, null, null, messageList, null,
                SocketState.CLOSED);

        List<IdentifierResponse> responseList = new LinkedList<>();
        responseList.add(new IdentifierResponse("BasicMac1", responseOne));
        responseList.add(new IdentifierResponse("BasicMac2", responseOne));
        responseList.add(new IdentifierResponse("BasicMac3", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteFirst", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteLast", responseOne));
        responseList.add(new IdentifierResponse("PlainOnlyPadding", responseTwo));
        responseList.add(new IdentifierResponse("PlainTooMuchPadding", responseTwo));
        responseList.add(new IdentifierResponse("InvPadValMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadValMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd", responseOne));

        String description = "We know who is responsible for this behavior. This vulnerability is still in the process of beeing patched. \n"
                + "We will add information once it is patched.";
        knownVulnList.add(new KnownPaddingOracleVulnerability("- To be announced -", "- To be announced -",
                "- To be announced -", PaddingOracleStrength.STRONG, true, knownVulnableSuites, knownNotVulnableSuites,
                description, affectedProducts, responseList, false));

        return knownVulnList;
    }

    private List<KnownPaddingOracleVulnerability> createUnpatchedTwo() {
        List<KnownPaddingOracleVulnerability> knownVulnList = new LinkedList<>();
        List<CipherSuite> knownVulnableSuites = new LinkedList<>();
        List<CipherSuite> knownNotVulnableSuites = new LinkedList<>();

        List<String> affectedProducts = new LinkedList<>();
        affectedProducts.add("- To be announced -");
        affectedProducts.add("- To be announced -");
        List<ProtocolMessage> messageList = new LinkedList<>();
        AlertMessage alert = new AlertMessage();
        alert.setDescription(AlertDescription.BAD_RECORD_MAC.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.CLOSE_NOTIFY.getValue());
        alert.setLevel(AlertLevel.WARNING.getValue());
        messageList.add(alert);
        ResponseFingerprint responseTwo = new ResponseFingerprint(false, true, 2, 2, null, null, messageList, null,
                SocketState.CLOSED);
        messageList = new LinkedList<>();
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.BAD_RECORD_MAC.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        ResponseFingerprint responseOne = new ResponseFingerprint(false, true, 1, 1, null, null, messageList, null,
                SocketState.TIMEOUT);

        List<IdentifierResponse> responseList = new LinkedList<>();
        responseList.add(new IdentifierResponse("BasicMac1", responseOne));
        responseList.add(new IdentifierResponse("BasicMac2", responseOne));
        responseList.add(new IdentifierResponse("BasicMac3", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteFirst", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteLast", responseOne));
        responseList.add(new IdentifierResponse("PlainOnlyPadding", responseOne));
        responseList.add(new IdentifierResponse("PlainTooMuchPadding", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart0", responseTwo));
        responseList.add(new IdentifierResponse("ValPadInvMacMid0", responseTwo));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd0", responseTwo));

        responseList.add(new IdentifierResponse("InvPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadValMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd", responseOne));

        String description = "We know who is responsible for this behavior. This vulnerability is still in the process of beeing patched. \n"
                + "We will add information once it is patched.";
        knownVulnList.add(new KnownPaddingOracleVulnerability("- To be announced -", "- To be announced -",
                "- To be announced -", PaddingOracleStrength.STRONG, true, knownVulnableSuites, knownNotVulnableSuites,
                description, affectedProducts, responseList, false));

        return knownVulnList;
    }

    private List<KnownPaddingOracleVulnerability> createUnpatchedThree() {
        List<KnownPaddingOracleVulnerability> knownVulnList = new LinkedList<>();
        List<CipherSuite> knownVulnableSuites = new LinkedList<>();

        List<CipherSuite> knownNotVulnableSuites = new LinkedList<>();

        List<String> affectedProducts = new LinkedList<>();
        affectedProducts.add("- To be announced -");
        affectedProducts.add("- To be announced -");
        List<ProtocolMessage> messageList = new LinkedList<>();
        AlertMessage alert = new AlertMessage();
        alert.setDescription(AlertDescription.BAD_RECORD_MAC.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.CLOSE_NOTIFY.getValue());
        alert.setLevel(AlertLevel.WARNING.getValue());
        messageList.add(alert);
        ResponseFingerprint responseOne = new ResponseFingerprint(false, true, 2, 2, null, null, messageList, null,
                SocketState.CLOSED);
        messageList = new LinkedList<>();
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.DECODE_ERROR.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.CLOSE_NOTIFY.getValue());
        alert.setLevel(AlertLevel.WARNING.getValue());
        messageList.add(alert);
        ResponseFingerprint responseTwo = new ResponseFingerprint(false, true, 2, 2, null, null, messageList, null,
                SocketState.CLOSED);

        List<IdentifierResponse> responseList = new LinkedList<>();
        responseList.add(new IdentifierResponse("BasicMac1", responseOne));
        responseList.add(new IdentifierResponse("BasicMac2", responseOne));
        responseList.add(new IdentifierResponse("BasicMac3", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteFirst", responseTwo));
        responseList.add(new IdentifierResponse("MissingMacByteLast", responseTwo));
        responseList.add(new IdentifierResponse("PlainOnlyPadding", responseTwo));
        responseList.add(new IdentifierResponse("PlainTooMuchPadding", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadValMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd", responseOne));

        String description = "We know who is responsible for this behavior. This vulnerability is still in the process of beeing patched. \n"
                + "We will add information once it is patched.";
        knownVulnList.add(new KnownPaddingOracleVulnerability("- To be announced -", "- To be announced -",
                "- To be announced -", PaddingOracleStrength.STRONG, false, knownVulnableSuites,
                knownNotVulnableSuites, description, affectedProducts, responseList, false));

        return knownVulnList;
    }

    private List<KnownPaddingOracleVulnerability> createCve20196485() {
        List<KnownPaddingOracleVulnerability> knownVulnList = new LinkedList<>();
        List<CipherSuite> knownVulnableSuites = new LinkedList<>();
        List<CipherSuite> knownNotVulnableSuites = new LinkedList<>();

        List<String> affectedProducts = new LinkedList<>();
        affectedProducts.add("Citrix ADC and NetScaler Gateway version 12.1 earlier than build 50.31");
        affectedProducts.add("Citrix ADC and NetScaler Gateway version 12.0 earlier than build 60.9");
        affectedProducts.add("Citrix ADC and NetScaler Gateway version 11.1 earlier than build 60.14");
        affectedProducts.add("Citrix ADC and NetScaler Gateway version 11.0 earlier than build 72.17");
        affectedProducts.add("Citrix ADC and NetScaler Gateway version 10.5 earlier than build 69.5");
        List<ProtocolMessage> messageList = new LinkedList<>();
        AlertMessage alert = new AlertMessage();
        // Other variant
        alert.setDescription(AlertDescription.BAD_RECORD_MAC.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        ResponseFingerprint responseOne = new ResponseFingerprint(false, true, 1, 1, null, null, messageList, null,
                SocketState.SOCKET_EXCEPTION);
        messageList = new LinkedList<>();
        ResponseFingerprint responseTwo = new ResponseFingerprint(false, false, 0, 0, null, null, messageList, null,
                SocketState.SOCKET_EXCEPTION);
        ResponseFingerprint responseThree = new ResponseFingerprint(false, false, 0, 0, null, null, messageList, null,
                SocketState.TIMEOUT);

        List<IdentifierResponse> responseList = new LinkedList<>();
        responseList.add(new IdentifierResponse("BasicMac1", responseTwo));
        responseList.add(new IdentifierResponse("BasicMac2", responseTwo));
        responseList.add(new IdentifierResponse("BasicMac3", responseTwo));
        responseList.add(new IdentifierResponse("MissingMacByteFirst", responseTwo));
        responseList.add(new IdentifierResponse("MissingMacByteLast", responseTwo));
        responseList.add(new IdentifierResponse("PlainOnlyPadding", responseTwo));
        responseList.add(new IdentifierResponse("PlainTooMuchPadding", responseTwo));
        responseList.add(new IdentifierResponse("InvPadValMacStart0", responseThree));
        responseList.add(new IdentifierResponse("InvPadValMacMid0", responseThree));
        responseList.add(new IdentifierResponse("InvPadValMacEnd0", responseTwo));

        responseList.add(new IdentifierResponse("ValPadInvMacStart0", responseTwo));
        responseList.add(new IdentifierResponse("ValPadInvMacMid0", responseTwo));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd0", responseTwo));

        responseList.add(new IdentifierResponse("InvPadInvMacStart0", responseTwo));
        responseList.add(new IdentifierResponse("InvPadInvMacMid0", responseTwo));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd0", responseTwo));

        responseList.add(new IdentifierResponse("InvPadValMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd", responseTwo));

        responseList.add(new IdentifierResponse("ValPadInvMacStart", responseTwo));
        responseList.add(new IdentifierResponse("ValPadInvMacMid", responseTwo));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd", responseTwo));

        responseList.add(new IdentifierResponse("InvPadInvMacStart", responseTwo));
        responseList.add(new IdentifierResponse("InvPadInvMacMid", responseTwo));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd", responseTwo));

        String description = "A vulnerability has been identified in the Citrix Application Delivery Controller (ADC)\n"
                + "formally known as NetScaler ADC and NetScaler Gateway platforms using hardware acceleration that \n"
                + "could allow an attacker to exploit the appliance to decrypt TLS traffic. This vulnerability does \n"
                + "not directly allow an attacker to obtain the TLS private key.\n "
                + "\n "
                + "More Details: https://support.citrix.com/article/CTX240139";
        knownVulnList.add(new KnownPaddingOracleVulnerability("CVE-2019-6485", "Citrix CVE-2019-6485",
                "Citrix NetScaler CVE-2019-6485", PaddingOracleStrength.POODLE, true, knownVulnableSuites,
                knownNotVulnableSuites, description, affectedProducts, responseList, false));

        return knownVulnList;
    }

    private List<KnownPaddingOracleVulnerability> createCve20191559() {
        List<KnownPaddingOracleVulnerability> knownVulnList = new LinkedList<>();
        List<CipherSuite> knownVulnableSuites = new LinkedList<>();
        List<CipherSuite> knownNotVulnableSuites = new LinkedList<>();

        List<String> affectedProducts = new LinkedList<>();
        affectedProducts.add("Openssl < 1.0.2r");
        List<ProtocolMessage> messageList = new LinkedList<>();
        AlertMessage alert = new AlertMessage();
        // Other variant
        alert.setDescription(AlertDescription.BAD_RECORD_MAC.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.CLOSE_NOTIFY.getValue());
        alert.setLevel(AlertLevel.WARNING.getValue());
        messageList.add(alert);

        ResponseFingerprint responseOne = new ResponseFingerprint(false, true, 2, 2, null, null, messageList, null,
                SocketState.CLOSED);
        messageList = new LinkedList<>();
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.BAD_RECORD_MAC.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);

        alert = new AlertMessage();
        alert.setDescription(AlertDescription.CLOSE_NOTIFY.getValue());
        alert.setLevel(AlertLevel.WARNING.getValue());
        messageList.add(alert);

        ResponseFingerprint responseTwo = new ResponseFingerprint(false, true, 2, 2, null, null, messageList, null,
                SocketState.TIMEOUT);

        List<IdentifierResponse> responseList = new LinkedList<>();
        responseList.add(new IdentifierResponse("BasicMac1", responseOne));
        responseList.add(new IdentifierResponse("BasicMac2", responseOne));
        responseList.add(new IdentifierResponse("BasicMac3", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteFirst", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteLast", responseOne));
        responseList.add(new IdentifierResponse("PlainOnlyPadding", responseOne));
        responseList.add(new IdentifierResponse("PlainTooMuchPadding", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart0", responseTwo));
        responseList.add(new IdentifierResponse("ValPadInvMacMid0", responseTwo));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd0", responseTwo));

        responseList.add(new IdentifierResponse("InvPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadValMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd", responseOne));

        String description = "If an application encounters a fatal protocol error and then calls\n"
                + "SSL_shutdown() twice (once to send a close_notify, and once to receive one) then\n"
                + "OpenSSL can respond differently to the calling application if a 0 byte record is\n"
                + "received with invalid padding compared to if a 0 byte record is received with an\n"
                + "invalid MAC. If the application then behaves differently based on that in a way\n"
                + "that is detectable to the remote peer, then this amounts to a padding oracle\n"
                + "that could be used to decrypt data.\n" + "\n"
                + "In order for this to be exploitable then \"non-stitched\" ciphersuites must be in\n"
                + "use. Stitched ciphersuites are optimised implementations of certain commonly\n"
                + "used ciphersuites. Also the application must call SSL_shutdown() twice even if a\n"
                + "protocol error has occurred (applications should not do this but some do\n" + "anyway).\n" + "\n"
                + "This issue does not impact OpenSSL 1.1.1 or 1.1.0.\n" + "\n"
                + "OpenSSL 1.0.2 users should upgrade to 1.0.2r.\n";
        knownVulnList.add(new KnownPaddingOracleVulnerability("Openssl CVE-2019-1559", "Openssl CVE-2019-1559",
                "Openssl CVE-2019-1559", PaddingOracleStrength.STRONG, true, knownVulnableSuites,
                knownNotVulnableSuites, description, affectedProducts, responseList, false));

        return knownVulnList;
    }

    private List<KnownPaddingOracleVulnerability> createCve20162107() {
        List<KnownPaddingOracleVulnerability> knownVulnList = new LinkedList<>();
        List<CipherSuite> knownVulnableSuites = new LinkedList<>();
        knownVulnableSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        knownVulnableSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);

        List<CipherSuite> knownNotVulnableSuites = new LinkedList<>();
        knownNotVulnableSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384);
        knownNotVulnableSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384);
        knownNotVulnableSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        knownNotVulnableSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
        for (CipherSuite suite : CipherSuite.values()) {
            if (!suite.name().contains("AES")) {
                knownNotVulnableSuites.add(suite);
            }
        }

        List<String> affectedProducts = new LinkedList<>();
        affectedProducts.add("Openssl < 1.0.1t (after Lucky13 patch)");
        affectedProducts.add("Openssl < 1.0.2h (after Lucky13 patch)");
        List<ProtocolMessage> messageList = new LinkedList<>();
        AlertMessage alert = new AlertMessage();
        alert.setDescription(AlertDescription.BAD_RECORD_MAC.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        ResponseFingerprint responseOne = new ResponseFingerprint(false, true, 1, 1, null, null, messageList, null,
                SocketState.CLOSED);
        messageList = new LinkedList<>();
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.RECORD_OVERFLOW.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        ResponseFingerprint responseTwo = new ResponseFingerprint(false, true, 1, 1, null, null, messageList, null,
                SocketState.CLOSED);

        List<IdentifierResponse> responseList = new LinkedList<>();
        responseList.add(new IdentifierResponse("BasicMac1", responseOne));
        responseList.add(new IdentifierResponse("BasicMac2", responseOne));
        responseList.add(new IdentifierResponse("BasicMac3", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteFirst", responseOne));
        responseList.add(new IdentifierResponse("MissingMacByteLast", responseOne));
        responseList.add(new IdentifierResponse("PlainOnlyPadding", responseTwo));
        responseList.add(new IdentifierResponse("PlainTooMuchPadding", responseTwo));
        responseList.add(new IdentifierResponse("InvPadValMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid0", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd0", responseOne));

        responseList.add(new IdentifierResponse("InvPadValMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadValMacEnd", responseOne));

        responseList.add(new IdentifierResponse("ValPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("ValPadInvMacEnd", responseOne));

        responseList.add(new IdentifierResponse("InvPadInvMacStart", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacMid", responseOne));
        responseList.add(new IdentifierResponse("InvPadInvMacEnd", responseOne));

        // Other variant
        messageList = new LinkedList<>();
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.BAD_RECORD_MAC.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.CLOSE_NOTIFY.getValue());
        alert.setLevel(AlertLevel.WARNING.getValue());
        messageList.add(alert);

        responseOne = new ResponseFingerprint(false, true, 2, 2, null, null, messageList, null, SocketState.CLOSED);
        messageList = new LinkedList<>();
        alert = new AlertMessage();
        alert.setDescription(AlertDescription.RECORD_OVERFLOW.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        messageList.add(alert);

        alert = new AlertMessage();
        alert.setDescription(AlertDescription.CLOSE_NOTIFY.getValue());
        alert.setLevel(AlertLevel.WARNING.getValue());
        messageList.add(alert);

        responseTwo = new ResponseFingerprint(false, true, 2, 2, null, null, messageList, null, SocketState.CLOSED);

        List<IdentifierResponse> responseListB = new LinkedList<>();
        responseListB.add(new IdentifierResponse("BasicMac1", responseOne));
        responseListB.add(new IdentifierResponse("BasicMac2", responseOne));
        responseListB.add(new IdentifierResponse("BasicMac3", responseOne));
        responseListB.add(new IdentifierResponse("MissingMacByteFirst", responseOne));
        responseListB.add(new IdentifierResponse("MissingMacByteLast", responseOne));
        responseListB.add(new IdentifierResponse("PlainOnlyPadding", responseTwo));
        responseListB.add(new IdentifierResponse("PlainTooMuchPadding", responseTwo));
        responseListB.add(new IdentifierResponse("InvPadValMacStart0", responseOne));
        responseListB.add(new IdentifierResponse("InvPadValMacMid0", responseOne));
        responseListB.add(new IdentifierResponse("InvPadValMacEnd0", responseOne));

        responseListB.add(new IdentifierResponse("ValPadInvMacStart0", responseOne));
        responseListB.add(new IdentifierResponse("ValPadInvMacMid0", responseOne));
        responseListB.add(new IdentifierResponse("ValPadInvMacEnd0", responseOne));

        responseListB.add(new IdentifierResponse("InvPadInvMacStart0", responseOne));
        responseListB.add(new IdentifierResponse("InvPadInvMacMid0", responseOne));
        responseListB.add(new IdentifierResponse("InvPadInvMacEnd0", responseOne));

        responseListB.add(new IdentifierResponse("InvPadValMacStart", responseOne));
        responseListB.add(new IdentifierResponse("InvPadValMacMid", responseOne));
        responseListB.add(new IdentifierResponse("InvPadValMacEnd", responseOne));

        responseListB.add(new IdentifierResponse("ValPadInvMacStart", responseOne));
        responseListB.add(new IdentifierResponse("ValPadInvMacMid", responseOne));
        responseListB.add(new IdentifierResponse("ValPadInvMacEnd", responseOne));

        responseListB.add(new IdentifierResponse("InvPadInvMacStart", responseOne));
        responseListB.add(new IdentifierResponse("InvPadInvMacMid", responseOne));
        responseListB.add(new IdentifierResponse("InvPadInvMacEnd", responseOne));

        String description = "A MITM attacker can use a padding oracle attack to decrypt traffic\n"
                + "when the connection uses an AES CBC cipher and the server support\n" + "AES-NI.\n" + "\n"
                + "This issue was introduced as part of the fix for Lucky 13 padding\n"
                + "attack (CVE-2013-0169). The padding check was rewritten to be in\n"
                + "constant time by making sure that always the same bytes are read and\n"
                + "compared against either the MAC or padding bytes. But it no longer\n"
                + "checked that there was enough data to have both the MAC and padding\n" + "bytes.\n" + "\n"
                + "OpenSSL 1.0.2 users should upgrade to 1.0.2h\n" + "OpenSSL 1.0.1 users should upgrade to 1.0.1t\n"
                + "\n" + "This issue was reported to OpenSSL on 13th of April 2016 by Juraj\n"
                + "Somorovsky using TLS-Attacker. The fix was developed by Kurt Roeckx\n"
                + "of the OpenSSL development team.";
        knownVulnList.add(new KnownPaddingOracleVulnerability("CVE-2016-2107", "UnluckyHMAC",
                "UnluckyHMAC (CVE-2016-2107)", PaddingOracleStrength.WEAK, false, knownVulnableSuites,
                knownNotVulnableSuites, description, affectedProducts, responseList, false));
        knownVulnList.add(new KnownPaddingOracleVulnerability("CVE-2016-2107", "UnluckyHMAC",
                "UnluckyHMAC (CVE-2016-2107)", PaddingOracleStrength.WEAK, false, knownVulnableSuites,
                knownNotVulnableSuites, description, affectedProducts, responseListB, false));

        return knownVulnList;
    }

    public KnownPaddingOracleVulnerability getKnownVulnerability(
            List<PaddingOracleCipherSuiteFingerprint> fingerPrintList) {
        LOGGER.trace("Trying to attribute PaddingOracle to a Known Vulnerability");
        for (KnownPaddingOracleVulnerability vulnerability : knownVulnerabilityList) {
            if (!checkCipherSuitesPlausible(vulnerability, fingerPrintList)) {
                LOGGER.trace("Ciphersuites are not plausible for " + vulnerability.getCve());
                continue;
            }
            if (!checkTestVectorResponseListPlausible(vulnerability, fingerPrintList)) {
                LOGGER.trace("Responses are not plausible for " + vulnerability.getCve());
                continue;
            }
            LOGGER.trace("Vulnerability identified as " + vulnerability.getCve());
            return vulnerability;
        }
        LOGGER.trace("Vulnerability not found in Database");
        return null;
    }

    private boolean checkCipherSuitesPlausible(KnownPaddingOracleVulnerability vulnerability,
            List<PaddingOracleCipherSuiteFingerprint> fingerPrintList) {
        for (CipherSuite suite : vulnerability.getKnownAffectedCiphersuites()) {
            for (PaddingOracleCipherSuiteFingerprint fingerprint : fingerPrintList) {
                if (fingerprint.getSuite() == suite && !Objects.equals(fingerprint.getVulnerable(), Boolean.TRUE)) {
                    return false;
                }
            }
        }
        for (CipherSuite suite : vulnerability.getKnownNotAffectedCiphersuites()) {
            for (PaddingOracleCipherSuiteFingerprint fingerprint : fingerPrintList) {
                if (fingerprint.getSuite() == suite && Objects.equals(fingerprint.getVulnerable(), Boolean.TRUE)) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean checkTestVectorResponseListPlausible(KnownPaddingOracleVulnerability vulnerability,
            List<PaddingOracleCipherSuiteFingerprint> fingerPrintList) {
        List<VectorResponse> vulnerableVectorResponseList = null;
        for (PaddingOracleCipherSuiteFingerprint fingerprint : fingerPrintList) {
            if (Objects.equals(fingerprint.getVulnerable(), Boolean.TRUE) && !fingerprint.isShakyScans()) {
                vulnerableVectorResponseList = fingerprint.getResponseMapList().get(0);
            }
        }
        if (vulnerableVectorResponseList == null) {
            return false;
        }
        for (VectorResponse vulnResponse : vulnerableVectorResponseList) {
            boolean found = false;
            for (IdentifierResponse response : vulnerability.getResponseIdentification()) {
                if (response.getIdentifier().equals(vulnResponse.getPaddingVector().getIdentifier())) {
                    found = true;
                    if (FingerPrintChecker.checkSimpleEquality(response.getFingerprint(),
                            vulnResponse.getFingerprint(), true) != EqualityError.NONE) {
                        return false;
                    }
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }
}
