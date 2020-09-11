/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.serverscanner.vectorStatistics;

import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsscanner.serverscanner.leak.info.DirectRaccoonOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.directRaccoon.DirectRaccoonWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidCurve.InvalidCurveVector;
import de.rub.nds.tlsscanner.serverscanner.util.FisherExactTest;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author marcel
 */
public class distributionTestRun {
    public static void main(String[] args) {
        List<ProtocolMessage> messageList = new LinkedList<>();
        List<AbstractRecord> recordList  = new LinkedList<>();
        SocketState socketState;
        produceFisherOverview();
        
        Record demoRecord = new Record();
        demoRecord.setCompleteRecordBytes(new byte[10]);
        demoRecord.setLength(10);
        demoRecord.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        demoRecord.setProtocolVersion(new byte[2]);
        messageList.add(new ClientHelloMessage());
        recordList.add(demoRecord);
        
        ResponseFingerprint fp = new ResponseFingerprint(messageList, recordList, SocketState.CLOSED);
        ResponseFingerprint fp2 = new ResponseFingerprint(messageList, recordList, SocketState.TIMEOUT);
        ResponseFingerprint fp3 = new ResponseFingerprint(messageList, recordList, SocketState.DATA_AVAILABLE);
        ResponseFingerprint fp4 = new ResponseFingerprint(messageList, recordList, SocketState.IO_EXCEPTION);
        ResponseFingerprint fp5 = new ResponseFingerprint(messageList, recordList, SocketState.SOCKET_EXCEPTION);
        InvalidCurveVector testVec = new InvalidCurveVector(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384, NamedGroup.BRAINPOOLP256R1, ECPointFormat.UNCOMPRESSED, false, false, null);
        List<VectorResponse> vectorResponses = new LinkedList<>();
        
        int uncommon = 5;
        int uncommon2 = 1;
        
        for(int i = 0; i < (100 - uncommon - 1 * uncommon2); i++) {
            vectorResponses.add(new VectorResponse(testVec, fp));
        }
        for(int i = 0; i < uncommon; i++) {
            vectorResponses.add(new VectorResponse(testVec, fp2));
        }
        for(int i = 0; i < uncommon2; i++) {
            vectorResponses.add(new VectorResponse(testVec, fp3));
        }
        /*for(int i = 0; i < uncommon2; i++) {
            vectorResponses.add(new VectorResponse(testVec, fp4));
        }
        for(int i = 0; i < uncommon2; i++) {
            vectorResponses.add(new VectorResponse(testVec, fp5));
        }*/
        
        
        DistributionTest distTest = new DistributionTest(new DirectRaccoonOracleTestInfo(CipherSuite.GREASE_10, ProtocolVersion.TLS13, DirectRaccoonWorkflowType.CKE),
        vectorResponses, 80, 20);
        System.out.println("Distinct: " + distTest.isSignificantDistinctAnswers());
        
        produceFisherOverview();
    }
    
    private static void produceFisherOverview() {
        List<ProtocolMessage> messageList = new LinkedList<>();
        List<AbstractRecord> recordList  = new LinkedList<>();
        SocketState socketState;
        
        Record demoRecord = new Record();
        demoRecord.setCompleteRecordBytes(new byte[10]);
        demoRecord.setLength(10);
        demoRecord.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        demoRecord.setProtocolVersion(new byte[2]);
        messageList.add(new ClientHelloMessage());
        recordList.add(demoRecord);
        
        ResponseFingerprint fp = new ResponseFingerprint(messageList, recordList, SocketState.CLOSED);
        ResponseFingerprint fp2 = new ResponseFingerprint(messageList, recordList, SocketState.TIMEOUT);
        
        
        
        InvalidCurveVector testVec = new InvalidCurveVector(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384, NamedGroup.BRAINPOOLP256R1, ECPointFormat.UNCOMPRESSED, false, false, null);
        
        
        for(int uncommon = 0; uncommon <= 50; uncommon++) {
            List<VectorResponse> vectorResponses = new LinkedList<>();
            for(int i = 0; i < (100 - uncommon); i++) {
                vectorResponses.add(new VectorResponse(testVec, fp));
            }
            for(int i = 0; i < uncommon; i++) {
                vectorResponses.add(new VectorResponse(testVec, fp2));
            }
            
            DistributionTest distTest = new DistributionTest(new DirectRaccoonOracleTestInfo(CipherSuite.GREASE_10, ProtocolVersion.TLS13, DirectRaccoonWorkflowType.CKE),
                vectorResponses, 80, 20);
            System.out.println("Distribution: " + (100 - uncommon) + "|" + uncommon + " -> Reject Sidechannel:" + distTest.isSignificantDistinctAnswers());
        }
    }
    
    private static void produceChiSquareOverview() {
        List<ProtocolMessage> messageList = new LinkedList<>();
        List<AbstractRecord> recordList  = new LinkedList<>();
        SocketState socketState;
        
        Record demoRecord = new Record();
        demoRecord.setCompleteRecordBytes(new byte[10]);
        demoRecord.setLength(10);
        demoRecord.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        demoRecord.setProtocolVersion(new byte[2]);
        messageList.add(new ClientHelloMessage());
        recordList.add(demoRecord);
        
        ResponseFingerprint fp = new ResponseFingerprint(messageList, recordList, SocketState.CLOSED);
        ResponseFingerprint fp2 = new ResponseFingerprint(messageList, recordList, SocketState.TIMEOUT);

        InvalidCurveVector testVec = new InvalidCurveVector(ProtocolVersion.TLS12, CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384, NamedGroup.BRAINPOOLP256R1, ECPointFormat.UNCOMPRESSED, false, false, null);
        
    }
}
