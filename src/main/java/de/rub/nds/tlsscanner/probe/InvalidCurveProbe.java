/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttacker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.invalidCurve.InvalidCurvePoint;
import de.rub.nds.tlsscanner.probe.invalidCurve.TwistedCurvePoint;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.InvalidCurveResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class InvalidCurveProbe extends TlsProbe {

    private TestResult supportsEphemeral;

    private TestResult supportsStatic;
    
    private TestResult supportsRenegotiation;
    
    private List<ProtocolVersion> supportedProtocolVersions;
    
    private List<NamedGroup> supportedFpGroups;
    
    private List<NamedGroup> supportedTls13FpGroups;
    
    private HashMap<ProtocolVersion, List<CipherSuite>> supportedECDHCipherSuites;
    
    private List<ECPointFormat> supportedFpPointFormats;   

    public InvalidCurveProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.INVALID_CURVE, config, 10);
    }

    @Override
    public ProbeResult executeTest() {
        TestResult vulnerableClassic = TestResult.NOT_TESTED_YET;
        TestResult vulnerableEphemeral = TestResult.NOT_TESTED_YET;
        TestResult vulnerableTwist = TestResult.NOT_TESTED_YET;
        
        //ScannerDetail scanDetail = scannerConfig.getScanDetail();
        
        for(ProtocolVersion protocolVersion: supportedProtocolVersions)
        {
            if(protocolVersion != ProtocolVersion.TLS12) {continue;}
            List<NamedGroup> groupList;
            if(protocolVersion == ProtocolVersion.TLS13)
            {
                groupList = supportedTls13FpGroups;
            }
            else
            {
                groupList = supportedFpGroups;
            }
            for(int i = 0; i < supportedECDHCipherSuites.get(protocolVersion).size(); i++)
            {
                for(NamedGroup group: groupList)
                {
                    InvalidCurveAttackConfig invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig().getGeneralDelegate());
                    invalidCurveAttackConfig.setNamedGroup(group);
                    invalidCurveAttackConfig.setPublicPointBaseX(InvalidCurvePoint.fromNamedGroup(group).getPublicPointBaseX());
                    invalidCurveAttackConfig.setPublicPointBaseY(InvalidCurvePoint.fromNamedGroup(group).getPublicPointBaseY());
                    invalidCurveAttackConfig.setProtocolFlows(InvalidCurvePoint.fromNamedGroup(group).getOrder().intValue() * 2);
                    invalidCurveAttackConfig.setPointCompressionFormat(ECPointFormat.UNCOMPRESSED);
                    
                    /*if(supportsRenegotiation == TestResult.TRUE && protocolVersion == ProtocolVersion.TLS13)
                    {
                        invalidCurveAttackConfig.setAttackInRenegotiation(true);
                    }*/
                    
                    InvalidCurveAttacker attacker = prepareAttacker(invalidCurveAttackConfig, protocolVersion, supportedECDHCipherSuites.get(protocolVersion).get(i), group);
                    Boolean vulnerable = attacker.isVulnerable();
                    
                    Boolean twistVulnerable = false;
                    if(TwistedCurvePoint.fromIntendedNamedGroup(group) != null)
                    { 
                        //Check for twist attacks
                        for(ECPointFormat format: supportedFpPointFormats)
                        {
                            InvalidCurveAttackConfig TwistedCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig().getGeneralDelegate());
                            TwistedCurveAttackConfig.setNamedGroup(group);
                            TwistedCurveAttackConfig.setPublicPointBaseX(TwistedCurvePoint.fromIntendedNamedGroup(group).getPublicPointBaseX());
                            TwistedCurveAttackConfig.setPublicPointBaseY(TwistedCurvePoint.fromIntendedNamedGroup(group).getPublicPointBaseY());
                            TwistedCurveAttackConfig.setProtocolFlows(TwistedCurvePoint.fromIntendedNamedGroup(group).getOrder().intValue() * 2);
                            TwistedCurveAttackConfig.setPointCompressionFormat(format);
                            
                            EllipticCurveOverFp intendedCurve = (EllipticCurveOverFp)CurveFactory.getCurve(group);
                            BigInteger modA = intendedCurve.getA().getData().multiply(TwistedCurvePoint.fromIntendedNamedGroup(group).getD()).mod(intendedCurve.getModulus());
                            BigInteger modB = intendedCurve.getB().getData().multiply(TwistedCurvePoint.fromIntendedNamedGroup(group).getD()).mod(intendedCurve.getModulus());
                            EllipticCurveOverFp twistedCurve = new EllipticCurveOverFp(modA, modB, intendedCurve.getModulus());
                            
                            TwistedCurveAttackConfig.setTwistedCurve(twistedCurve);
                            TwistedCurveAttackConfig.setCurveTwistAttack(true);
                            TwistedCurveAttackConfig.setCurveTwistD(TwistedCurvePoint.fromIntendedNamedGroup(group).getD());
                            
                            InvalidCurveAttacker twistAttacker = prepareAttacker(TwistedCurveAttackConfig, protocolVersion, supportedECDHCipherSuites.get(protocolVersion).get(i), group);
                            
                            twistVulnerable = twistAttacker.isVulnerable();   
                        }
                    }
                    
                    if(vulnerable == null)
                    {
                        LOGGER.warn("Was unable to test for vulnerability");
                    }
                    else if(vulnerable && supportedECDHCipherSuites.get(protocolVersion).get(i).isEphemeral())
                    {
                        vulnerableEphemeral = TestResult.TRUE;
                    }
                    else if(vulnerable)
                    {
                        vulnerableClassic = TestResult.TRUE;
                    }
                    
                    if(twistVulnerable == null)
                    {
                        LOGGER.warn("Was unable to test for twist vulnerability");
                    }
                    else if(twistVulnerable)
                    {
                        vulnerableTwist = TestResult.TRUE;
                    }
                }
            }  
        }
        return new InvalidCurveResult(vulnerableClassic, vulnerableEphemeral, vulnerableTwist);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_ECDH) != TestResult.FALSE || report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) != TestResult.FALSE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportsEphemeral = report.getResult(AnalyzedProperty.SUPPORTS_ECDH);
        supportsStatic = report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH);
        supportsRenegotiation = report.getResult(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION);
        
        System.out.println("Renegotiation: " + report.getResult(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION).toString());
        
        List<NamedGroup> groups = new LinkedList<>();
        for(NamedGroup group : report.getSupportedNamedGroups())
        {
            if(group.isCurve() && CurveFactory.getCurve(group) instanceof EllipticCurveOverFp)
            {
                groups.add(group);
            }
        }
                   
        HashMap<ProtocolVersion,List<CipherSuite>> cipherSuitesMap = new HashMap<>();
        for(VersionSuiteListPair pair: report.getVersionSuitePairs())
        {
            if(!cipherSuitesMap.containsKey(pair.getVersion()))
            {
                cipherSuitesMap.put(pair.getVersion(), new LinkedList<>());
            }
            for(CipherSuite cipherSuite: pair.getCiphersuiteList())
            {
                if(cipherSuite.name().contains("TLS_ECDH"))
                {
                    cipherSuitesMap.get(pair.getVersion()).add(cipherSuite);
                }
            }
            
        }
        
        List<ECPointFormat> fpPointFormats = new LinkedList<>();
        if(report.getResult(AnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT) == TestResult.TRUE)
        {
            fpPointFormats.add(ECPointFormat.UNCOMPRESSED);
        }
        if(report.getResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME) == TestResult.TRUE)
        {
            fpPointFormats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        }
        
        List<ProtocolVersion> protocolVersions = new LinkedList<>();
        if(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.TRUE)
        {
            protocolVersions.add(ProtocolVersion.TLS10);
        }
        if(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.TRUE)
        {
            protocolVersions.add(ProtocolVersion.TLS11);
        }
        if(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.TRUE)
        {
            protocolVersions.add(ProtocolVersion.TLS12);
        }
        if(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE)
        {
            protocolVersions.add(ProtocolVersion.TLS13);
            List<NamedGroup> tls13groups = new LinkedList();
            for(NamedGroup group: report.getSupportedTls13Groups())
            {
                if(group != NamedGroup.ECDH_X25519 && group != NamedGroup.ECDH_X448 && CurveFactory.getCurve(group) instanceof EllipticCurveOverFp)
                {
                    tls13groups.add(group);
                }
            }
            
            List<CipherSuite> tls13CipherSuites = new LinkedList<>();
            for(CipherSuite cipherSuite: report.getSupportedTls13CipherSuites())
            {
                if(cipherSuite.isImplemented())
                {
                    tls13CipherSuites.add(cipherSuite);
                }
            }
            cipherSuitesMap.put(ProtocolVersion.TLS13,tls13CipherSuites);
            supportedTls13FpGroups = tls13groups;
        }
        
        supportedFpPointFormats = fpPointFormats;
        supportedProtocolVersions = protocolVersions;
        supportedFpGroups = groups;
        supportedECDHCipherSuites = cipherSuitesMap;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new InvalidCurveResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }
    
    private InvalidCurveAttacker prepareAttacker(InvalidCurveAttackConfig attackConfig, ProtocolVersion protocolVersion, CipherSuite cipherSuite, NamedGroup group)
    {
       ClientDelegate delegate = (ClientDelegate) attackConfig.getDelegate(ClientDelegate.class);
       delegate.setHost(getScannerConfig().getClientDelegate().getHost());
       delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
       StarttlsDelegate starttlsDelegate = (StarttlsDelegate) attackConfig.getDelegate(StarttlsDelegate.class);
       starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
       InvalidCurveAttacker attacker = new InvalidCurveAttacker(attackConfig, attackConfig.createConfig());
       
       if(protocolVersion == ProtocolVersion.TLS13)
       {
           attacker.getTlsConfig().setAddKeyShareExtension(true);
           attacker.getTlsConfig().setAddECPointFormatExtension(false);
           attacker.getTlsConfig().setAddSupportedVersionsExtension(true);
           attacker.getTlsConfig().setDefaultKeySharePrivateKey(new BigInteger("1"));
       }
       
       attacker.getTlsConfig().setHighestProtocolVersion(protocolVersion);
       attacker.getTlsConfig().setDefaultSelectedProtocolVersion(protocolVersion);
       attacker.getTlsConfig().setDefaultClientSupportedCiphersuites(cipherSuite);
       attacker.getTlsConfig().setDefaultClientNamedGroups(group);
       attacker.getTlsConfig().setDefaultSelectedNamedGroup(group);
       
       return attacker;
    }

}
