/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.response;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class FingerprintCheckerTest {

    public static HandshakeMessage parseMessage(
            byte msgType, int msgLength, byte[] msgVersion, byte[] completeMsg) {
        HandshakeMessage returnMessage;

        if (msgType == HandshakeMessageType.CLIENT_HELLO.getValue()) {
            ClientHelloMessage message = new ClientHelloMessage();
            message.setType(msgType);
            message.setLength(msgLength);
            message.setProtocolVersion(msgVersion);
            message.setCompleteResultingMessage(completeMsg);

            returnMessage = message;
            return returnMessage;
        } else if (msgType == HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue()) {
            ClientHelloMessage message = new ClientHelloMessage();
            message.setType(msgType);
            message.setLength(msgLength);
            message.setCompleteResultingMessage(completeMsg);

            returnMessage = message;
            return returnMessage;
        } else if (msgType == HandshakeMessageType.SERVER_HELLO.getValue()) {
            ServerHelloMessage message = new ServerHelloMessage();
            message.setType(msgType);
            message.setLength(msgLength);
            message.setProtocolVersion(msgVersion);
            message.setCompleteResultingMessage(completeMsg);

            returnMessage = message;
            return returnMessage;
        } else if (msgType == HandshakeMessageType.CERTIFICATE.getValue()) {
            CertificateMessage message = new CertificateMessage();
            message.setType(msgType);
            message.setLength(msgLength);
            message.setCompleteResultingMessage(completeMsg);

            returnMessage = message;
            return returnMessage;
        } else if (msgType == HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue()) {
            ServerHelloMessage message = new ServerHelloMessage();
            message.setType(msgType);
            message.setLength(msgLength);
            message.setCompleteResultingMessage(completeMsg);

            returnMessage = message;
            return returnMessage;
        } else if (msgType == HandshakeMessageType.SERVER_HELLO_DONE.getValue()) {
            ServerHelloDoneMessage message = new ServerHelloDoneMessage();
            message.setType(msgType);
            message.setLength(msgLength);
            message.setCompleteResultingMessage(completeMsg);

            returnMessage = message;
            return returnMessage;

        } else {
            return null;
        }
    }

    public static Record parseRecord(
            ProtocolMessageType recordType,
            byte[] recordVersion,
            int recordLength,
            byte[] completeRecord) {
        Record record = new Record();
        record.setContentMessageType(recordType);
        record.setContentType(recordType.getValue());
        record.setProtocolVersion(recordVersion);
        record.setLength(recordLength);
        record.setCompleteRecordBytes(completeRecord);
        return record;
    }

    public static List<Arguments> provideTestVectors() {
        HandshakeMessage clientHelloMsg =
                parseMessage(
                        HandshakeMessageType.CLIENT_HELLO.getValue(),
                        508,
                        ProtocolVersion.TLS12.getValue(),
                        DataConverter.hexStringToByteArray(
                                "010001fc03036ced07c5f0707d08d6c98ab375b523236492233a56eaec0d8feb2565ba7c337720c6b3ba7f6fdf5c643a038d40b56a8db014a6c90359432f3ccbb6db40fa76a9200022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035010001910000001a00180000157777772e7363686e6569657266616374732e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00204ca75275f38541b0628d64892200b8b184c7b7fd836b4c8c9b3124e753d7577a00170041040c6eae5febeb82f27d09c5cb7155682da96bf0863aeaff721f556885790a3819449702afd594b8c088aa1ea4effaf210867a0c0e430ad460ffe16847b6d1cbc4002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c0002400100150081000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
        Record clientHelloRecord =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS10.getValue(),
                        512,
                        DataConverter.hexStringToByteArray(
                                "1603010200010001fc03036ced07c5f0707d08d6c98ab375b523236492233a56eaec0d8feb2565ba7c337720c6b3ba7f6fdf5c643a038d40b56a8db014a6c90359432f3ccbb6db40fa76a9200022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035010001910000001a00180000157777772e7363686e6569657266616374732e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00204ca75275f38541b0628d64892200b8b184c7b7fd836b4c8c9b3124e753d7577a00170041040c6eae5febeb82f27d09c5cb7155682da96bf0863aeaff721f556885790a3819449702afd594b8c088aa1ea4effaf210867a0c0e430ad460ffe16847b6d1cbc4002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c0002400100150081000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
        Record clientHelloRecordDiffContent =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS10.getValue(),
                        512,
                        DataConverter.hexStringToByteArray("00"));

        HandshakeMessage clientKeyExchangeMsg =
                parseMessage(
                        HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue(),
                        33,
                        null,
                        DataConverter.hexStringToByteArray(
                                "10000021208e379c1834609dc10e8185b2ba501d7337523bffb2c945c4011b3541b4c95d09"));
        Record clientKeyExchangeRecord =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS12.getValue(),
                        37,
                        DataConverter.hexStringToByteArray(
                                "160303002510000021208e379c1834609dc10e8185b2ba501d7337523bffb2c945c4011b3541b4c95d09"));

        ServerHelloMessage serverHelloMsg =
                (ServerHelloMessage)
                        parseMessage(
                                HandshakeMessageType.SERVER_HELLO.getValue(),
                                74,
                                ProtocolVersion.TLS12.getValue(),
                                DataConverter.hexStringToByteArray(
                                        "0200004a03030fa96863574fc48715a6aa266f5f954a2a3fbcaa6a359b663c21dde3c71e6f2400c030000022ff0100010000000000000b0004030001020023000000100005000302683200170000"));
        Record serverHelloRecord =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS12.getValue(),
                        78,
                        DataConverter.hexStringToByteArray(
                                "160303004e0200004a03030fa96863574fc48715a6aa266f5f954a2a3fbcaa6a359b663c21dde3c71e6f2400c030000022ff0100010000000000000b0004030001020023000000100005000302683200170000"));
        Record serverHelloRecordDiffContent =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS12.getValue(),
                        78,
                        DataConverter.hexStringToByteArray("00"));

        HandshakeMessage certificateMsg =
                parseMessage(
                        HandshakeMessageType.CERTIFICATE.getValue(),
                        4050,
                        null,
                        DataConverter.hexStringToByteArray(
                                "0b000fd2000fcf000548308205443082042ca00302010202120448be9136570b1e6ae7e09a3e4ad15a5281300d06092a864886f70d01010b05003032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b3009060355040313025233301e170d3232303531323036333630385a170d3232303831303036333630375a3020311e301c060355040313157777772e7363686e6569657266616374732e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100a03f359b2d8bc342608ef2f8ace6bac736cf41e88c40e33d788588ac58c8f2a4802de3380a3a9fdf28030bfda403a26174e373a8a7b25b620c8d52e3e82780fd777945e81f8442d864e811094c1bca0dfe17f03c758ccfd7f44ac7ecb3bba0ba7ab0bb77622d7b9f434f761a138c95d5a49924fe687f3b7af959ff2a8735705e660a9abdcfb85cd88b48dd36d936760969c3bedd65cdb9d27ebbd9095ab03a6a1723f1ad0df9f46f119b964a03f1940128a836dad6ba4ef34c132c782b13d1841303487c96bd9ac7f169d00bc135cf08be4ef996c67efa2bd43cddb19a03145e9e7317080e80c922d6a57c38404b739f1aa6893ac7a6453772e446d744a6b1350203010001a382026430820260300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e04160414ec4d430b42883b6201ad767417fb31189563f4ff301f0603551d23041830168014142eb317b75856cbae500940e61faf9d8b14c2c6305506082b0601050507010104493047302106082b060105050730018615687474703a2f2f72332e6f2e6c656e63722e6f7267302206082b060105050730028616687474703a2f2f72332e692e6c656e63722e6f72672f30330603551d11042c302a82117363686e6569657266616374732e636f6d82157777772e7363686e6569657266616374732e636f6d304c0603551d20044530433008060667810c0102013037060b2b0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6f726730820105060a2b06010401d6790204020481f60481f300f1007600dfa55eab68824f1f6cadeeb85f4e3e5aeacda212a46a5e8e3b12c020445c2a7300000180b7324cbf0000040300473045022076db1ef32753938a56523bb6f7fecc4d285779b8ba5bac2834a7bc39356a851b022100806f2f164c27d813ed51c6d08fe07b34a25b3c5cd6f36217497fc0b646ff06740077002979bef09e393921f056739f63a577e5be577d9c600af8f94d5d265c255dc78400000180b7324e6b0000040300483046022100b65f5e49e1d5dcd4fe251083056bdc54e89eb25e311999bc32fe46f9de51f198022100f0ffd3f3ac9e93cf501d17925ec5ca893ff365122fe5f4353990bb48c3a1436b300d06092a864886f70d01010b0500038201010028b565c4ccda33af8e0a3d8198c35de8e6006fb494d0dee506e70725c535291eb9c162d87735c0238b3ff9ed309bbf4041c93491b0ebf9fb318e7c537fc17bc0e0925ef495603a7175efaf4153eee473c0f698697c5498c6cfbc82d963b1ae041fc9a70047fcec63ea52052dde8a4b8c2238d018a20dc052f04ae8a37c268109ccddea391d67889cc40dba2d35d2808a37638b935490ede377a0d72cbc42d33e1777768231f5e7d192c3ed0d99a7fc93f5e93b31a925f5e34f07ea4f515ef1a817c6187a44a7fa94be088f53741b7783fda685abed06eb45b2998484997247f0dc5776b2928de0aa54cc09e5f3face6b2375c6c46da28a9a177fee95f9855ba900051a30820516308202fea003020102021100912b084acf0c18a753f6d62e25a75f5a300d06092a864886f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f74205831301e170d3230303930343030303030305a170d3235303931353136303030305a3032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b300906035504031302523330820122300d06092a864886f70d01010105000382010f003082010a0282010100bb021528ccf6a094d30f12ec8d5592c3f882f199a67a4288a75d26aab52bb9c54cb1af8e6bf975c8a3d70f4794145535578c9ea8a23919f5823c42a94e6ef53bc32edb8dc0b05cf35938e7edcf69f05a0b1bbec094242587fa3771b313e71cace19befdbe43b45524596a9c153ce34c852eeb5aeed8fde6070e2a554abb66d0e97a540346b2bd3bc66eb66347cfa6b8b8f572999f830175dba726ffb81c5add286583d17c7e709bbf12bf786dcc1da715dd446e3ccad25c188bc60677566b3f118f7a25ce653ff3a88b647a5ff1318ea9809773f9d53f9cf01e5f5a6701714af63a4ff99b3939ddc53a706fe48851da169ae2575bb13cc5203f5ed51a18bdb150203010001a382010830820104300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601050507030206082b0601050507030130120603551d130101ff040830060101ff020100301d0603551d0e04160414142eb317b75856cbae500940e61faf9d8b14c2c6301f0603551d2304183016801479b459e67bb6e5e40173800888c81a58f6e99b6e303206082b0601050507010104263024302206082b060105050730028616687474703a2f2f78312e692e6c656e63722e6f72672f30270603551d1f0420301e301ca01aa0188616687474703a2f2f78312e632e6c656e63722e6f72672f30220603551d20041b30193008060667810c010201300d060b2b0601040182df13010101300d06092a864886f70d01010b0500038202010085ca4e473ea3f7854485bcd56778b29863ad754d1e963d336572542d81a0eac3edf820bf5fccb77000b76e3bf65e94dee4209fa6ef8bb203e7a2b5163c91ceb4ed3902e77c258a47e6656e3f46f4d9f0ce942bee54ce12bc8c274bb8c1982fa2afcd71914a08b7c8b8237b042d08f908573e83d904330a472178098227c32ac89bb9ce5cf264c8c0be79c04f8e6d440c5e92bb2ef78b10e1e81d4429db5920ed63b921f81226949357a01d6504c10a22ae100d4397a1181f7ee0e08637b55ab1bd30bf876e2b2aff214e1b05c3f51897f05eacc3a5b86af02ebc3b33b9ee4bdeccfce4af840b863fc0554336f668e136176a8e99d1ffa540a734b7c0d063393539756ef2ba76c89302e9a94b6c17ce0c02d9bd81fb9fb768d40665b3823d7753f88e7903ad0a3107752a43d8559772c4290ef7c45d4ec8ae468430d7f2855f18a179bbe75e708b07e18693c3b98fdc6171252aafdfed255052688b92dce5d6b5e3da7dd0876c842131ae82f5fbb9abc889173de14ce5380ef6bd2bbd968114ebd5db3d20a77e59d3e2f858f95bb848cdfe5c4f1629fe1e5523afc811b08dea7c9390172ffdaca20947463ff0e9b0b7ff284d6832d6675e1e69a393b8f59d8b2f0bd25243a66f3257654d3281df3853855d7e5d6629eab8dde495b5cdb5561242cdc44ec6253844506decce005518fee94964d44eca979cb45bc073a8abb847c20005643082056030820448a00302010202104001772137d4e942b8ee76aa3c640ab7300d06092a864886f70d01010b0500303f31243022060355040a131b4469676974616c205369676e617475726520547275737420436f2e311730150603550403130e44535420526f6f74204341205833301e170d3231303132303139313430335a170d3234303933303138313430335a304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f7420583130820222300d06092a864886f70d01010105000382020f003082020a0282020100ade82473f41437f39b9e2b57281c87bedcb7df38908c6e3ce657a078f775c2a2fef56a6ef6004f28dbde68866c4493b6b163fd14126bbf1fd2ea319b217ed1333cba48f5dd79dfb3b8ff12f1219a4bc18a8671694a66666c8f7e3c70bfad292206f3e4c0e680aee24b8fb7997e94039fd347977c99482353e838ae4f0a6f832ed149578c8074b6da2fd0388d7b0370211b75f2303cfa8faeddda63abeb164fc28e114b7ecf0be8ffb5772ef4b27b4ae04c12250c708d0329a0e15324ec13d9ee19bf10b34a8c3f89a36151deac870794f46371ec2ee26f5b9881e1895c34796c76ef3b906279e6dba49a2f26c5d010e10eded9108e16fbb7f7a8f7c7e50207988f360895e7e237960d36759efb0e72b11d9bbc03f94905d881dd05b42ad641e9ac0176950a0fd8dfd5bd121f352f28176cd298c1a80964776e4737baceac595e689d7f72d689c50641293e593edd26f524c911a75aa34c401f46a199b5a73a516e863b9e7d72a712057859ed3e5178150b038f8dd02f05b23e7b4a1c4b730512fcc6eae050137c439374b3ca74e78e1f0108d030d45b7136b407bac130305c48b7823b98a67d608aa2a32982ccbabd83041ba2830341a1d605f11bc2b6f0a87c863b46a8482a88dc769a76bf1f6aa53d198feb38f364dec82b0d0a28fff7dbe21542d422d0275de179fe18e77088ad4ee6d98b3ac6dd27516effbc64f533434f0203010001a382014630820142300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106304b06082b06010505070101043f303d303b06082b06010505073002862f687474703a2f2f617070732e6964656e74727573742e636f6d2f726f6f74732f647374726f6f74636178332e703763301f0603551d23041830168014c4a7b1a47b2c71fadbe14b9075ffc4156085891030540603551d20044d304b3008060667810c010201303f060b2b0601040182df130101013030302e06082b060105050702011622687474703a2f2f6370732e726f6f742d78312e6c657473656e63727970742e6f7267303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c2e6964656e74727573742e636f6d2f445354524f4f544341583343524c2e63726c301d0603551d0e0416041479b459e67bb6e5e40173800888c81a58f6e99b6e300d06092a864886f70d01010b050003820101000a73006c966eff0e52d0aedd8ce75a06ad2fa8e38fbfc90a031550c2e56c42bb6f9bf4b44fc244880875cceb079b14626e78deec27ba395cf5a2a16e5694701053b1bbe4afd0a2c32b01d496f4c5203533f9d86136e0718db4b8b5aa824595c0f2a92328e7d6a1cb6708daa0432caa1b931fc9def5ab695d13f55b865822ca4d55e470676dc257c5463941cf8a5883586d99fe57e8360ef00e23aafd8897d0e35c0e9449b5b51735d22ebf4e85ef18e08592eb063b6c29230960dc45024c12183be9fb0ededc44f85898aeeabd4545a1885d66cafe10e96f82c811420dfbe9ece38600de9d10e338faa47db1d8e8498284069b2be86b4f010c38772ef9dde739"));
        Record certificateRecord =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS12.getValue(),
                        4054,
                        DataConverter.hexStringToByteArray(
                                "1603030fd60b000fd2000fcf000548308205443082042ca00302010202120448be9136570b1e6ae7e09a3e4ad15a5281300d06092a864886f70d01010b05003032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b3009060355040313025233301e170d3232303531323036333630385a170d3232303831303036333630375a3020311e301c060355040313157777772e7363686e6569657266616374732e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100a03f359b2d8bc342608ef2f8ace6bac736cf41e88c40e33d788588ac58c8f2a4802de3380a3a9fdf28030bfda403a26174e373a8a7b25b620c8d52e3e82780fd777945e81f8442d864e811094c1bca0dfe17f03c758ccfd7f44ac7ecb3bba0ba7ab0bb77622d7b9f434f761a138c95d5a49924fe687f3b7af959ff2a8735705e660a9abdcfb85cd88b48dd36d936760969c3bedd65cdb9d27ebbd9095ab03a6a1723f1ad0df9f46f119b964a03f1940128a836dad6ba4ef34c132c782b13d1841303487c96bd9ac7f169d00bc135cf08be4ef996c67efa2bd43cddb19a03145e9e7317080e80c922d6a57c38404b739f1aa6893ac7a6453772e446d744a6b1350203010001a382026430820260300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e04160414ec4d430b42883b6201ad767417fb31189563f4ff301f0603551d23041830168014142eb317b75856cbae500940e61faf9d8b14c2c6305506082b0601050507010104493047302106082b060105050730018615687474703a2f2f72332e6f2e6c656e63722e6f7267302206082b060105050730028616687474703a2f2f72332e692e6c656e63722e6f72672f30330603551d11042c302a82117363686e6569657266616374732e636f6d82157777772e7363686e6569657266616374732e636f6d304c0603551d20044530433008060667810c0102013037060b2b0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6f726730820105060a2b06010401d6790204020481f60481f300f1007600dfa55eab68824f1f6cadeeb85f4e3e5aeacda212a46a5e8e3b12c020445c2a7300000180b7324cbf0000040300473045022076db1ef32753938a56523bb6f7fecc4d285779b8ba5bac2834a7bc39356a851b022100806f2f164c27d813ed51c6d08fe07b34a25b3c5cd6f36217497fc0b646ff06740077002979bef09e393921f056739f63a577e5be577d9c600af8f94d5d265c255dc78400000180b7324e6b0000040300483046022100b65f5e49e1d5dcd4fe251083056bdc54e89eb25e311999bc32fe46f9de51f198022100f0ffd3f3ac9e93cf501d17925ec5ca893ff365122fe5f4353990bb48c3a1436b300d06092a864886f70d01010b0500038201010028b565c4ccda33af8e0a3d8198c35de8e6006fb494d0dee506e70725c535291eb9c162d87735c0238b3ff9ed309bbf4041c93491b0ebf9fb318e7c537fc17bc0e0925ef495603a7175efaf4153eee473c0f698697c5498c6cfbc82d963b1ae041fc9a70047fcec63ea52052dde8a4b8c2238d018a20dc052f04ae8a37c268109ccddea391d67889cc40dba2d35d2808a37638b935490ede377a0d72cbc42d33e1777768231f5e7d192c3ed0d99a7fc93f5e93b31a925f5e34f07ea4f515ef1a817c6187a44a7fa94be088f53741b7783fda685abed06eb45b2998484997247f0dc5776b2928de0aa54cc09e5f3face6b2375c6c46da28a9a177fee95f9855ba900051a30820516308202fea003020102021100912b084acf0c18a753f6d62e25a75f5a300d06092a864886f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f74205831301e170d3230303930343030303030305a170d3235303931353136303030305a3032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b300906035504031302523330820122300d06092a864886f70d01010105000382010f003082010a0282010100bb021528ccf6a094d30f12ec8d5592c3f882f199a67a4288a75d26aab52bb9c54cb1af8e6bf975c8a3d70f4794145535578c9ea8a23919f5823c42a94e6ef53bc32edb8dc0b05cf35938e7edcf69f05a0b1bbec094242587fa3771b313e71cace19befdbe43b45524596a9c153ce34c852eeb5aeed8fde6070e2a554abb66d0e97a540346b2bd3bc66eb66347cfa6b8b8f572999f830175dba726ffb81c5add286583d17c7e709bbf12bf786dcc1da715dd446e3ccad25c188bc60677566b3f118f7a25ce653ff3a88b647a5ff1318ea9809773f9d53f9cf01e5f5a6701714af63a4ff99b3939ddc53a706fe48851da169ae2575bb13cc5203f5ed51a18bdb150203010001a382010830820104300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601050507030206082b0601050507030130120603551d130101ff040830060101ff020100301d0603551d0e04160414142eb317b75856cbae500940e61faf9d8b14c2c6301f0603551d2304183016801479b459e67bb6e5e40173800888c81a58f6e99b6e303206082b0601050507010104263024302206082b060105050730028616687474703a2f2f78312e692e6c656e63722e6f72672f30270603551d1f0420301e301ca01aa0188616687474703a2f2f78312e632e6c656e63722e6f72672f30220603551d20041b30193008060667810c010201300d060b2b0601040182df13010101300d06092a864886f70d01010b0500038202010085ca4e473ea3f7854485bcd56778b29863ad754d1e963d336572542d81a0eac3edf820bf5fccb77000b76e3bf65e94dee4209fa6ef8bb203e7a2b5163c91ceb4ed3902e77c258a47e6656e3f46f4d9f0ce942bee54ce12bc8c274bb8c1982fa2afcd71914a08b7c8b8237b042d08f908573e83d904330a472178098227c32ac89bb9ce5cf264c8c0be79c04f8e6d440c5e92bb2ef78b10e1e81d4429db5920ed63b921f81226949357a01d6504c10a22ae100d4397a1181f7ee0e08637b55ab1bd30bf876e2b2aff214e1b05c3f51897f05eacc3a5b86af02ebc3b33b9ee4bdeccfce4af840b863fc0554336f668e136176a8e99d1ffa540a734b7c0d063393539756ef2ba76c89302e9a94b6c17ce0c02d9bd81fb9fb768d40665b3823d7753f88e7903ad0a3107752a43d8559772c4290ef7c45d4ec8ae468430d7f2855f18a179bbe75e708b07e18693c3b98fdc6171252aafdfed255052688b92dce5d6b5e3da7dd0876c842131ae82f5fbb9abc889173de14ce5380ef6bd2bbd968114ebd5db3d20a77e59d3e2f858f95bb848cdfe5c4f1629fe1e5523afc811b08dea7c9390172ffdaca20947463ff0e9b0b7ff284d6832d6675e1e69a393b8f59d8b2f0bd25243a66f3257654d3281df3853855d7e5d6629eab8dde495b5cdb5561242cdc44ec6253844506decce005518fee94964d44eca979cb45bc073a8abb847c20005643082056030820448a00302010202104001772137d4e942b8ee76aa3c640ab7300d06092a864886f70d01010b0500303f31243022060355040a131b4469676974616c205369676e617475726520547275737420436f2e311730150603550403130e44535420526f6f74204341205833301e170d3231303132303139313430335a170d3234303933303138313430335a304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f7420583130820222300d06092a864886f70d01010105000382020f003082020a0282020100ade82473f41437f39b9e2b57281c87bedcb7df38908c6e3ce657a078f775c2a2fef56a6ef6004f28dbde68866c4493b6b163fd14126bbf1fd2ea319b217ed1333cba48f5dd79dfb3b8ff12f1219a4bc18a8671694a66666c8f7e3c70bfad292206f3e4c0e680aee24b8fb7997e94039fd347977c99482353e838ae4f0a6f832ed149578c8074b6da2fd0388d7b0370211b75f2303cfa8faeddda63abeb164fc28e114b7ecf0be8ffb5772ef4b27b4ae04c12250c708d0329a0e15324ec13d9ee19bf10b34a8c3f89a36151deac870794f46371ec2ee26f5b9881e1895c34796c76ef3b906279e6dba49a2f26c5d010e10eded9108e16fbb7f7a8f7c7e50207988f360895e7e237960d36759efb0e72b11d9bbc03f94905d881dd05b42ad641e9ac0176950a0fd8dfd5bd121f352f28176cd298c1a80964776e4737baceac595e689d7f72d689c50641293e593edd26f524c911a75aa34c401f46a199b5a73a516e863b9e7d72a712057859ed3e5178150b038f8dd02f05b23e7b4a1c4b730512fcc6eae050137c439374b3ca74e78e1f0108d030d45b7136b407bac130305c48b7823b98a67d608aa2a32982ccbabd83041ba2830341a1d605f11bc2b6f0a87c863b46a8482a88dc769a76bf1f6aa53d198feb38f364dec82b0d0a28fff7dbe21542d422d0275de179fe18e77088ad4ee6d98b3ac6dd27516effbc64f533434f0203010001a382014630820142300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106304b06082b06010505070101043f303d303b06082b06010505073002862f687474703a2f2f617070732e6964656e74727573742e636f6d2f726f6f74732f647374726f6f74636178332e703763301f0603551d23041830168014c4a7b1a47b2c71fadbe14b9075ffc4156085891030540603551d20044d304b3008060667810c010201303f060b2b0601040182df130101013030302e06082b060105050702011622687474703a2f2f6370732e726f6f742d78312e6c657473656e63727970742e6f7267303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c2e6964656e74727573742e636f6d2f445354524f4f544341583343524c2e63726c301d0603551d0e0416041479b459e67bb6e5e40173800888c81a58f6e99b6e300d06092a864886f70d01010b050003820101000a73006c966eff0e52d0aedd8ce75a06ad2fa8e38fbfc90a031550c2e56c42bb6f9bf4b44fc244880875cceb079b14626e78deec27ba395cf5a2a16e5694701053b1bbe4afd0a2c32b01d496f4c5203533f9d86136e0718db4b8b5aa824595c0f2a92328e7d6a1cb6708daa0432caa1b931fc9def5ab695d13f55b865822ca4d55e470676dc257c5463941cf8a5883586d99fe57e8360ef00e23aafd8897d0e35c0e9449b5b51735d22ebf4e85ef18e08592eb063b6c29230960dc45024c12183be9fb0ededc44f85898aeeabd4545a1885d66cafe10e96f82c811420dfbe9ece38600de9d10e338faa47db1d8e8498284069b2be86b4f010c38772ef9dde739"));

        HandshakeMessage serverKeyExchangeMsg =
                parseMessage(
                        HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue(),
                        296,
                        null,
                        DataConverter.hexStringToByteArray(
                                "0c00012803001d20b01075b4fc33077e0d6f18cedd62f406a08fed7237c4439fbb102af43425b60908040100578090265cd0e4a5e4feb8efbf66adadea0c9d4b7b0b8d87c9d4b54236063a0a8de718e5821cac35678195b10febf6e87b70c1ea4bb90f880a8c1ee2a0adf7962923c08b3bc237507f52a9d6e112afaf1a81f66faefc2c3bc5a2c7efc885bd9eafb7c8ca1af7d6507f70723a2892e428627f9f3d1b4150bf09f9f0bc14c82298c65e219ecb31c41e4ccd9fd913bc41b8c85e4f7971744c4e9eb07fafede537a15f96d58e3d1d938fc280fc0a435248e41e0249ce671d64af44ed25cb2425bd8b3f3f00af6ba172146daadbea8e7062d6907f088e8e04ca4d457dbe45ec9ed2f40691251207f6ba7c3b31790d50cb02610fe203162bbecffb59c28862282477d0"));
        Record serverKeyExchangeRecord =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS12.getValue(),
                        300,
                        DataConverter.hexStringToByteArray(
                                "160303012c0c00012803001d20b01075b4fc33077e0d6f18cedd62f406a08fed7237c4439fbb102af43425b60908040100578090265cd0e4a5e4feb8efbf66adadea0c9d4b7b0b8d87c9d4b54236063a0a8de718e5821cac35678195b10febf6e87b70c1ea4bb90f880a8c1ee2a0adf7962923c08b3bc237507f52a9d6e112afaf1a81f66faefc2c3bc5a2c7efc885bd9eafb7c8ca1af7d6507f70723a2892e428627f9f3d1b4150bf09f9f0bc14c82298c65e219ecb31c41e4ccd9fd913bc41b8c85e4f7971744c4e9eb07fafede537a15f96d58e3d1d938fc280fc0a435248e41e0249ce671d64af44ed25cb2425bd8b3f3f00af6ba172146daadbea8e7062d6907f088e8e04ca4d457dbe45ec9ed2f40691251207f6ba7c3b31790d50cb02610fe203162bbecffb59c28862282477d0"));

        HandshakeMessage serverHelloDoneMsg =
                parseMessage(
                        HandshakeMessageType.SERVER_HELLO_DONE.getValue(),
                        0,
                        null,
                        DataConverter.hexStringToByteArray("0e000000"));
        Record serverHelloDoneRecord =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS12.getValue(),
                        4,
                        DataConverter.hexStringToByteArray("16030300040e000000"));

        // Data for Test with ClientHello, ClientKeyExchange
        List<ProtocolMessage> msgListTestClient = new LinkedList<>();
        List<Record> recordListTestClient = new LinkedList<>();
        List<Record> recordListTestClientWithContentError = new LinkedList<>();
        SocketState stateTestClient;
        EqualityError expectedResultClient;

        msgListTestClient.add(clientHelloMsg);
        msgListTestClient.add(clientKeyExchangeMsg);
        recordListTestClient.add(clientHelloRecord);
        recordListTestClient.add(clientKeyExchangeRecord);
        recordListTestClientWithContentError.add(clientHelloRecordDiffContent);
        recordListTestClientWithContentError.add(clientKeyExchangeRecord);
        stateTestClient = SocketState.UP;
        expectedResultClient = EqualityError.NONE;

        // Data for Test with ServerHello, Certificate, ServerKeyExchangeMsg, ServerHelloDone
        List<ProtocolMessage> msgListTestServer = new LinkedList<>();
        List<Record> recordListTestServer = new LinkedList<>();
        SocketState stateTestServer;
        EqualityError expectedResultServer;

        msgListTestServer.add(serverHelloMsg);
        msgListTestServer.add(certificateMsg);
        msgListTestServer.add(serverKeyExchangeMsg);
        msgListTestServer.add(serverHelloDoneMsg);
        recordListTestServer.add(serverHelloRecord);
        recordListTestServer.add(certificateRecord);
        recordListTestServer.add(serverKeyExchangeRecord);
        recordListTestServer.add(serverHelloDoneRecord);
        stateTestServer = SocketState.UP;
        expectedResultServer = EqualityError.NONE;

        // Data for test with expected EqualityError:
        // EqualityError.MESSAGE_CLASS
        // with PriorityCheck regarding EqualityError.RecordContent

        // generate clientHelloMsg with different Class
        HandshakeMessage clientHelloMsgDiffClass =
                parseMessage(
                        HandshakeMessageType.SERVER_HELLO.getValue(),
                        508,
                        ProtocolVersion.TLS12.getValue(),
                        DataConverter.hexStringToByteArray(
                                "010001fc03036ced07c5f0707d08d6c98ab375b523236492233a56eaec0d8feb2565ba7c337720c6b3ba7f6fdf5c643a038d40b56a8db014a6c90359432f3ccbb6db40fa76a9200022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035010001910000001a00180000157777772e7363686e6569657266616374732e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00204ca75275f38541b0628d64892200b8b184c7b7fd836b4c8c9b3124e753d7577a00170041040c6eae5febeb82f27d09c5cb7155682da96bf0863aeaff721f556885790a3819449702afd594b8c088aa1ea4effaf210867a0c0e430ad460ffe16847b6d1cbc4002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c0002400100150081000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));

        List<ProtocolMessage> msgListTestMsgClass = new LinkedList<>();
        EqualityError expectedResultMsgClass;

        msgListTestMsgClass.add(clientHelloMsgDiffClass);
        msgListTestMsgClass.add(clientKeyExchangeMsg);
        expectedResultMsgClass = EqualityError.MESSAGE_CLASS;

        // Data for test with expected EqualityError:
        // EqualityError.MESSAGE_CONTENT

        // generate clientHelloMsg with different Content
        ServerHelloMessage serverHelloMsgDiffContent =
                (ServerHelloMessage)
                        parseMessage(
                                HandshakeMessageType.SERVER_HELLO.getValue(),
                                74,
                                ProtocolVersion.TLS12.getValue(),
                                DataConverter.hexStringToByteArray(
                                        "0200004a03030fa96863574fc48715a6aa266f5f954a2a3fbcaa6a359b663c21dde3c71e6f2400c030000022ff0100010000000000000b0004030001020023000000100005000302683200170000"));
        ModifiableByteArray serverHelloRandomDiffContent = new ModifiableByteArray();
        serverHelloRandomDiffContent.setOriginalValue(
                ServerHelloMessage.getHelloRetryRequestRandom());
        assert serverHelloMsgDiffContent != null;
        serverHelloMsgDiffContent.setRandom(serverHelloRandomDiffContent);

        ModifiableByteArray serverHelloRandom = new ModifiableByteArray();
        serverHelloRandom.setOriginalValue(
                DataConverter.hexStringToByteArray(
                        "0fa96863574fc48715a6aa266f5f954a2a3fbcaa6a359b663c21dde3c71e6f24"));
        assert serverHelloMsg != null;
        serverHelloMsg.setRandom(serverHelloRandom);

        List<ProtocolMessage> msgListTestMsgContent = new LinkedList<>();
        EqualityError expectedResultMsgContent;

        msgListTestMsgContent.add(serverHelloMsgDiffContent);
        msgListTestMsgContent.add(certificateMsg);
        msgListTestMsgContent.add(serverKeyExchangeMsg);
        msgListTestMsgContent.add(serverHelloDoneMsg);

        expectedResultMsgContent = EqualityError.MESSAGE_CONTENT;

        // Data for test with expected EqualityError:
        // EqualityError.MESSAGE_COUNT

        List<ProtocolMessage> msgListTestMsgCount = new LinkedList<>();
        EqualityError expectedResultMsgCount;

        msgListTestMsgCount.add(clientHelloMsg);
        msgListTestMsgCount.add(clientKeyExchangeMsg);
        msgListTestMsgCount.add(clientKeyExchangeMsg);
        expectedResultMsgCount = EqualityError.MESSAGE_COUNT;

        // Data for test with expected EqualityError:
        // EqualityError.RECORD_CONTENT

        List<Record> recordListTestRecordContent = new LinkedList<>();
        EqualityError expectedResultRecordContent;

        recordListTestRecordContent.add(clientHelloRecordDiffContent);
        recordListTestRecordContent.add(clientKeyExchangeRecord);
        expectedResultRecordContent = EqualityError.RECORD_CONTENT;

        // Data for test with expected EqualityError:
        // EqualityError.RECORD_CONTENT_TYPE

        // generate clientHelloRecord with different ContentType
        Record clientHelloRecordDiffContentType =
                parseRecord(
                        ProtocolMessageType.APPLICATION_DATA,
                        ProtocolVersion.TLS10.getValue(),
                        512,
                        DataConverter.hexStringToByteArray(
                                "1603010200010001fc03036ced07c5f0707d08d6c98ab375b523236492233a56eaec0d8feb2565ba7c337720c6b3ba7f6fdf5c643a038d40b56a8db014a6c90359432f3ccbb6db40fa76a9200022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035010001910000001a00180000157777772e7363686e6569657266616374732e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00204ca75275f38541b0628d64892200b8b184c7b7fd836b4c8c9b3124e753d7577a00170041040c6eae5febeb82f27d09c5cb7155682da96bf0863aeaff721f556885790a3819449702afd594b8c088aa1ea4effaf210867a0c0e430ad460ffe16847b6d1cbc4002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c0002400100150081000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));

        List<Record> recordListTestRecordContentType = new LinkedList<>();
        EqualityError expectedResultRecordContentType;

        recordListTestRecordContentType.add(clientHelloRecordDiffContentType);
        recordListTestRecordContentType.add(clientKeyExchangeRecord);

        expectedResultRecordContentType = EqualityError.RECORD_CONTENT_TYPE;

        // Data for test with expected EqualityError:
        // EqualityError.RECORD_COUNT

        List<Record> recordListTestRecordCount = new LinkedList<>();
        EqualityError expectedResultRecordCount;

        recordListTestRecordCount.add(clientHelloRecord);
        recordListTestRecordCount.add(clientKeyExchangeRecord);
        recordListTestRecordCount.add(clientKeyExchangeRecord);
        expectedResultRecordCount = EqualityError.RECORD_COUNT;

        // Data for test with expected EqualityError:
        // EqualityError.RECORD_VERSION

        // generate ClientHelloRecord with different Version
        Record clientHelloRecordDiffVersion =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS12.getValue(),
                        512,
                        DataConverter.hexStringToByteArray(
                                "1603010200010001fc03036ced07c5f0707d08d6c98ab375b523236492233a56eaec0d8feb2565ba7c337720c6b3ba7f6fdf5c643a038d40b56a8db014a6c90359432f3ccbb6db40fa76a9200022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035010001910000001a00180000157777772e7363686e6569657266616374732e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00204ca75275f38541b0628d64892200b8b184c7b7fd836b4c8c9b3124e753d7577a00170041040c6eae5febeb82f27d09c5cb7155682da96bf0863aeaff721f556885790a3819449702afd594b8c088aa1ea4effaf210867a0c0e430ad460ffe16847b6d1cbc4002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c0002400100150081000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));

        List<Record> recordListTestRecordVersion = new LinkedList<>();
        EqualityError expectedResultRecordVersion;

        recordListTestRecordVersion.add(clientHelloRecordDiffVersion);
        recordListTestRecordVersion.add(clientKeyExchangeRecord);
        expectedResultRecordVersion = EqualityError.RECORD_VERSION;

        // Data for test with expected EqualityError:
        // EqualityError.SOCKET_STATE
        SocketState stateTestSocketState;
        EqualityError expectedResultSocketState;

        stateTestSocketState = SocketState.CLOSED;
        expectedResultSocketState = EqualityError.SOCKET_STATE;

        // Data for test with expected EqualityError:
        // EqualityError.MESSAGE_CLASS
        // with PriorityCheck regarding EqualityError.RecordContent
        List<ProtocolMessage> msgListTestMsgClassWithPriority = new LinkedList<>();
        EqualityError expectedResultMsgClassWithPriority;

        msgListTestMsgClassWithPriority.add(clientHelloMsgDiffClass);
        msgListTestMsgClassWithPriority.add(clientKeyExchangeMsg);
        expectedResultMsgClassWithPriority = EqualityError.MESSAGE_CLASS;

        // Data for test with expected EqualityError:
        // EqualityError.MessageContent
        // with PriorityCheck regarding EqualityError.RecordContent
        EqualityError expectedResultMsgContentWithPriority;
        expectedResultMsgContentWithPriority = EqualityError.MESSAGE_CONTENT;

        List<Record> recordListTestServerWithContentError = new LinkedList<>();

        recordListTestServerWithContentError.add(serverHelloRecordDiffContent);
        recordListTestServerWithContentError.add(certificateRecord);
        recordListTestServerWithContentError.add(serverKeyExchangeRecord);
        recordListTestServerWithContentError.add(serverHelloDoneRecord);

        // Data for test with expected EqualityError:
        // EqualityError.MESSAGE_COUNT
        // with PriorityCheck regarding EqualityError.RecordContent
        List<ProtocolMessage> msgListTestMsgCountWithPriority = new LinkedList<>();
        EqualityError expectedResultMsgCountWithPriority;

        msgListTestMsgCountWithPriority.add(clientHelloMsg);
        msgListTestMsgCountWithPriority.add(clientKeyExchangeMsg);
        msgListTestMsgCountWithPriority.add(clientKeyExchangeMsg);
        expectedResultMsgCountWithPriority = EqualityError.MESSAGE_COUNT;

        // Data for test with expected EqualityError:
        // EqualityError.RECORD_CONTENT_TYPE
        // with PriorityCheck regarding EqualityError.RecordContent

        // generate clientHelloRecord with different ContentType & different Content
        Record clientHelloRecordDiffContentTypeWithPriority =
                parseRecord(
                        ProtocolMessageType.APPLICATION_DATA,
                        ProtocolVersion.TLS10.getValue(),
                        512,
                        DataConverter.hexStringToByteArray("00"));

        List<Record> recordListTestRecordContentTypeWithPriority = new LinkedList<>();
        EqualityError expectedResultRecordContentTypeWithPriority;

        recordListTestRecordContentTypeWithPriority.add(
                clientHelloRecordDiffContentTypeWithPriority);
        recordListTestRecordContentTypeWithPriority.add(clientKeyExchangeRecord);

        expectedResultRecordContentTypeWithPriority = EqualityError.RECORD_CONTENT_TYPE;

        // Data for test with expected EqualityError:
        // EqualityError.RECORD_COUNT
        // with PriorityCheck regarding EqualityError.RecordContent

        List<Record> recordListTestRecordCountWithPriority = new LinkedList<>();
        EqualityError expectedResultRecordCountWithPriority;

        recordListTestRecordCountWithPriority.add(clientHelloRecordDiffContent);
        recordListTestRecordCountWithPriority.add(clientKeyExchangeRecord);
        recordListTestRecordCountWithPriority.add(clientKeyExchangeRecord);
        expectedResultRecordCountWithPriority = EqualityError.RECORD_COUNT;

        // Data for test with expected EqualityError:
        // EqualityError.RECORD_VERSION
        // with PriorityCheck regarding EqualityError.RecordContent

        // generate ClientHelloRecord with different Version & different Content
        Record clientHelloRecordDiffVersionWithPriority =
                parseRecord(
                        ProtocolMessageType.HANDSHAKE,
                        ProtocolVersion.TLS12.getValue(),
                        512,
                        DataConverter.hexStringToByteArray("00"));

        List<Record> recordListTestRecordVersionWithPriority = new LinkedList<>();
        EqualityError expectedResultRecordVersionWithPriority;

        recordListTestRecordVersionWithPriority.add(clientHelloRecordDiffVersionWithPriority);
        recordListTestRecordVersionWithPriority.add(clientKeyExchangeRecord);
        expectedResultRecordVersionWithPriority = EqualityError.RECORD_VERSION;

        // Data for test with expected EqualityError:
        // EqualityError.SOCKET_STATE
        // with PriorityCheck regarding EqualityError.RecordContent
        SocketState stateTestSocketStateWithPriority;
        EqualityError expectedResultSocketStateWithPriority;

        stateTestSocketStateWithPriority = SocketState.CLOSED;
        expectedResultSocketStateWithPriority = EqualityError.SOCKET_STATE;

        return List.of(
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        expectedResultClient),
                Arguments.of(
                        msgListTestServer,
                        recordListTestServer,
                        stateTestServer,
                        msgListTestServer,
                        recordListTestServer,
                        stateTestServer,
                        expectedResultServer),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestMsgClass,
                        recordListTestClient,
                        stateTestClient,
                        expectedResultMsgClass),
                Arguments.of(
                        msgListTestServer,
                        recordListTestServer,
                        stateTestServer,
                        msgListTestMsgContent,
                        recordListTestServer,
                        stateTestServer,
                        expectedResultMsgContent),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestMsgCount,
                        recordListTestClient,
                        stateTestClient,
                        expectedResultMsgCount),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestRecordContent,
                        stateTestClient,
                        expectedResultRecordContent),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestRecordContentType,
                        stateTestClient,
                        expectedResultRecordContentType),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestRecordCount,
                        stateTestClient,
                        expectedResultRecordCount),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestRecordVersion,
                        stateTestClient,
                        expectedResultRecordVersion),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestClient,
                        stateTestSocketState,
                        expectedResultSocketState),
                // Tests with PriorityCheck regarding EqualityError.Record_Content
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestMsgClassWithPriority,
                        recordListTestClientWithContentError,
                        stateTestClient,
                        expectedResultMsgClassWithPriority),
                Arguments.of(
                        msgListTestServer,
                        recordListTestServer,
                        stateTestServer,
                        msgListTestMsgContent,
                        recordListTestServerWithContentError,
                        stateTestServer,
                        expectedResultMsgContentWithPriority),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestMsgCountWithPriority,
                        recordListTestClientWithContentError,
                        stateTestClient,
                        expectedResultMsgCountWithPriority),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestRecordContentTypeWithPriority,
                        stateTestClient,
                        expectedResultRecordContentTypeWithPriority),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestRecordCountWithPriority,
                        stateTestClient,
                        expectedResultRecordCountWithPriority),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestRecordVersionWithPriority,
                        stateTestClient,
                        expectedResultRecordVersionWithPriority),
                Arguments.of(
                        msgListTestClient,
                        recordListTestClient,
                        stateTestClient,
                        msgListTestClient,
                        recordListTestClient,
                        stateTestSocketStateWithPriority,
                        expectedResultSocketStateWithPriority));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testCheckEquality(
            List<ProtocolMessage> providedMsgList1,
            List<Record> providedRecordList1,
            SocketState providedState1,
            List<ProtocolMessage> providedMsgList2,
            List<Record> providedRecordList2,
            SocketState providedState2,
            EqualityError expectedError) {
        ResponseFingerprint fingerprint1 =
                new ResponseFingerprint(providedMsgList1, providedRecordList1, providedState1);
        ResponseFingerprint fingerprint2 =
                new ResponseFingerprint(providedMsgList2, providedRecordList2, providedState2);
        assertEquals(expectedError, FingerprintChecker.checkEquality(fingerprint1, fingerprint2));
    }
}
