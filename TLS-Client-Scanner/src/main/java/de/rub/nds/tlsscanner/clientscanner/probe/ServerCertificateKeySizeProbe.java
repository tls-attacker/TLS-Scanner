/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.protocol.crypto.key.PrivateKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import java.math.BigInteger;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * This probe tests the minimum key sizes required in certificates. For now, this only covers RSA
 * keys. DSS(/DSA) and DH are not yet implemented.
 */
public class ServerCertificateKeySizeProbe extends TlsClientProbe {

    private static final BigInteger RSA_PUBLIC_KEY = BigInteger.valueOf(65537);

    private static final Map<Integer, RsaPrivateKey> RSA_KEYS =
            Map.of(
                    512,
                    new RsaPrivateKey(
                            new BigInteger(
                                    "ad0ccf57b277976a7ef324b1b8d76ba7a27ab3f08a4c3e897cfec005de8f13fcc73356bc5aff413ca50dbde3e41c61e7610652277e31acd09b094151accb0501",
                                    16),
                            new BigInteger(
                                    "ADC0AB14EF662B3EAF021DD39FC5E896E9C367EE6C1C45FDE960E8F4DB16E226B74639465E1628FD75B44EAB01881487919F98340F3B53ABB2AFD48DD946EEFD",
                                    16)),
                    768,
                    new RsaPrivateKey(
                            new BigInteger(
                                    "76b3059f830565b0ae53372a22aee1370479377630d2a6390657f79d780e412e91798bc869ffa209917846221c43886719bb450d5089e789e068e6d268d5e2b0ee1be4b82979b02bdd563ed74bc75d0cd1b65f949ed1cbabdca9fef4ca93d401",
                                    16),
                            new BigInteger(
                                    "DEE7EF4B335173650442DA0142B56F32881A8DCA3BB3BBCEA6B679F84419AEE3FD9FC861DE369738CB783B85CF15A6DF1AD0D7B1AB5E2D10CB0CE2D1934DFA9160BA536AA8C0BB9EF7AB0D4B683CFC02D6F67A73791F07F4A4D3261B3438D691",
                                    16)),
                    1024,
                    new RsaPrivateKey(
                            new BigInteger(
                                    "1a8437a24c6c0da8c39ee802f628e5eb0153b8a8571d3414833f84cbbc00dd3d51aab5764d7438a1b95261d2b66cc0d47a7c314922a893cb83461652d2fed8139e63a26d49390ccd2c183f5a5a1b05095b69dc83552e0e6cfc20bd02b779ebc33803a2d3b22666e8de607317cd896d197c039d0c50e454a20f6695cc082e98b5",
                                    16),
                            new BigInteger(
                                    "A50CC4B6102725AE9473B9890FA15F6174A6A57B3145E1F0F52E5E1384E3B4637729A0DC41B56847D263CFC9BCD5116A108046273DB9CAF31115375607ACD3033F20DC6302723B9FE7D5BD5433EC34C51F2B2EDAF9E8306596641BDA316BA1A3F0E9FA94DDD4F5F7BDB81E1E798876CAF6A536BC6AC26FD0230CD163CD26CC11",
                                    16)),
                    1536,
                    new RsaPrivateKey(
                            new BigInteger(
                                    "5d0a5cb31956054c83c61d873b76a6388d87f0528196482927e87c67a5d001462c123734e6fe066e1cb8f459ad934c4695a39f9b13dc0c42748c9326abb0828397e91f620de366ec157f650cafb19c04358cb2ee430de0d0ff7b5cfcedf72e9e2f67119006997b3cc32f52920e6218af50e28d83e8af45ddf94a525b5dc33ba8cf7fe876d00da1917c532451781eb321c5ff7f10d7cef8535397747c29a407a682c13a2e12688f3062245e8aa788195fde4f911117524a33cd64ecd931a7b151",
                                    16),
                            new BigInteger(
                                    "C16A2DBECB5F98DC4BB3CF525D2BD08190B0F093384FFB93F7E49EF6B6505183488CBC1F9F3AE2331E504502E3E54026369E63596663C0214469E2D3690564BDB59FC0B0068A604D67EB4C37B60F22442029E790D54E009BA6E83E6E5CC45A69B39FD61C8830A381CBCF07AADCFF0131C0D292F50E2FEAF48BAE3CB84A591ECD7F00AC32D72394DE70F7AACF59268AED1BE8509C02376209CD183E4C2FEF4402FCFAEE369D279C97CD0131A1005A9D306DD1D47B936DFCF613B16F5D34134C87",
                                    16)),
                    2048,
                    new RsaPrivateKey(
                            new BigInteger(
                                    "8fe29df10a39a0948bf816f6933bc1b939c4dc1aecf741165d1306e49d856377b1fb3af2a3a5d392fa873707ce8badacd3ccc2c0a5dd529e814e25c80d2d02399f253c3a6669f093292b1eeb364e33d3e4a1d616a266e51cc29098dbd4100eedf1b9a105a5c9875117cf8ece932bf4518e7267f81c662d913138514d3a3f8c10e5b8a9a482ab672d0d584fdb7fa9c378fc2ad6fdd5e173aa7c77c529b9a86f90227a4d97b9fc7a78866669de2450196a735ac5df540e97d939352ac54a75ab5618362202cfcd3b0c9bc8db8665fa05870a68565bb7232b4b18bc4d8c4049f3e3ab377495992deaa97985e91fd7e17c829126904341f5ddecb3adb1fea28d98c1",
                                    16),
                            new BigInteger(
                                    "CEAF69A4BE075524BE940F2A352947CE0EFB68D05591EC0E5AA353C29DF973A9653D866DF825A83F4848758354A279C92782CC2399A47988FA30C9F1A6F82420AFC70E234C1C51AE5B793329E911E0ADF234D965FD61F1BEF45BE802681E5C8C984E082A69C0C7D069C2E616B989FC2027E223E152177CE06FBC8069A496AE895F3AF7A8F99A6B7896F978B191E2BEFC75C248227B797C510007EB5D38C7986D91D1ED103EC8DC0A4287CEC65BA0E57808493BC977DA93623BADE767D9AEA7F3B497341227AEBADF1D15C4DB9707F9331D4C8A337E06FA18CE282B319197F3C805CC85370E8F0C250E2D36667D5758B8D5DBF9C94BB59F3E085AD3456210212F",
                                    16)),
                    3072,
                    new RsaPrivateKey(
                            new BigInteger(
                                    "034f9f39175c729ab88d348a6905dbdbc66b537832a2bcf44cea92554a98a8da361143c81c52378772ed419f79631bd090d4214ebea6dabd329b0891445a55369219efd1b04bed69776fd7116910453e545615d32857b97f680a94194d8eec7424bed0101d690288119d0b253305affceee4a67dd23bf8ae6a2266199c6b1fa1999d435da9db7669dd819334d1b96d86cdd0c109c83a4ae7149fa2cc17dec824e63ccebd5e844c609ef34903a9896e510b6cdaeafad5b28f056ec7e00d064c17d7b58ff9ce126cd7c1d5b4fbfd0db84b0be749aad39cc690049ebf30faa4c70f3463b2c0923f920a071e3ea35631f8e5676079ff1ba177e4333cf2e8a0626b60ed10faec535571f1dcac335a6f341688ad367e6cf0ad1b721379b14d602e2f71a65751653ba5d9d8659649fbb8993df45d28e7de5830e24b8cac1e5967e160adb9faac95439821eee7a4a43d4dd54aa2406e5681a7cbd8288c5f649975abaae1545f4e50b1c99490933cd883f844160a129977b2a7130921462470b6fa540379",
                                    16),
                            new BigInteger(
                                    "CA3B4BCD151FB92E528840CD8E057588C6497507E5FAA741945E4CCA8A5DDECE5B038AF1F2B7AC6A8457EE0ABD18DC5F963C27D0460C42D0D7BC0B86109AF9C61969324071F3862D888AF9DB4A1F90F69850ADFC38FE4AB536A1CB019699A68C18904C174166D0C77D858C9564A7BA012A21413EEBABC2899E5FF769D0EF8CB2C1EF8873C425489B8987726021F0132458A5C7D27E778FB75B8C632FA3294742A7E48EB70DFF424E9277C2ABE95B57AC6F27ECDFBB731750668B2AE7A3FD6758D225D3ABEC2B178C6FFE5F6658147946D876F00EA49F4E5E7F03C678EDC1DE2F97D3AFF3082C80A5F5E16FBCE3CBC83388B3C6382BC8A7FCF0C1D8F018FF0FAB684A3D4F4B5D2C1E18BD7DF96C00861639B09040AD60A72F8EDE158409E990EC68293C768466556064E22E05BA6E311A082C3725E8279D68ABD71A926F557BA26CBE636871C671A599A99F8876420407811C6357230D9708FB37E51D06BA0B65EE8A59854AE8EB157E65AACB5C75C8C38D0C0DD649717318858DDD25C3538C4F",
                                    16)),
                    4096,
                    new RsaPrivateKey(
                            new BigInteger(
                                    "92483b5d0ed93302673308e0725131ffaeb393368509aae134e6aa7ba12deeaec74af9f794cacaaa70d335a3e79ed376281d69434b56332b46b55554be1da00d091313d600c65cbb4c8bbd70042ae3dc64ffc21f59e3343c40ba6981eada06b0229e0968a1dcec77416090f43245fe175cae3e3c59c467bfb15711e31453ec946ae7f1d1424bd69ce43fad3a295826c2ea4df92a395343a7f10b1e576f1b8ba833df77f616b84cb6e4906ffd6bf875aa809c0c8568480df8755e84d2b27ae23b3249ba96e764c2937c066e2f3eebfcf4a09645e538d76ccdc4325024f12d8030e01d7e55cd274bf62b06099f2c43b77fef9239f776f9dc2fb2930539e8247ef971b9e5970775f5777d54618491b6702ff266833afa440df121518607e54632b383e892442ff907ec5d6623da275109a593ce03e7a0ce876a3d97b938a76f5df92855dcc4541d7f083a2c4254cc4ac7e60393eed5580491dfb0449cdd24e6eaa4d9ae6c3f73b516ea814901ea1b6b0f70f7d869d60549e103dd0218ee25c0e2bd30138808eeec28ff02448ba72b16c5b752f793367df192ba0d0fc22ef5b75042e56b0ec98b97b037e65f8f27810f05d1316a4780bbcb31e7326fc768abfb67adc96ed9104b73572d479cf731660bb1bfacdb80d5d989d2408a3d0afb6a42187c70305c723744cdcc432ea6b579e9bba9ff04bb4ed870fba47c5804a565a3aa21",
                                    16),
                            new BigInteger(
                                    "FAD3F213B85227C4F759691EB0E6F8DBF69E341C36935DCBE024DC6DF3456559BB40509B2B1A791E95FA0E2E214E8A3CD3CFA6855BE5F9B3525E3677BDBBCA318EFB0791B408F55E4129FD2BFEEBC77DE7EDC69EB328A9E88CEA25785EC2E7CD3642C0574F0D5D4F3A70191BD9F1A0F74DFB1A70C770FF30B1BA150F2536A7768096A75C8BA51A3348E90AF69EBDF75A7D29A68EC685A123A1791D220061B3559365F28C346B9751EAC361913408FC732A53E0E79E4D0DDFF081F4272346649376D55C4484EFFC327E22524652646D64DFB3BDB6DD2E98471C8A4CDF9599ADC77C3A6C083F956E40178D1868947F86B659B9DB4B22F3A6723E894ABF799A55645B35C7AB2194A1B3E9F47B91ED7665860195CE78547B5198D3E9F3FC2CBB7364149C78687C61AA0AA637F52ECB65506B926C04F103593860340379BDCA4E30DB42143A399C288EC6F4042F27FDEA7AD3BE2E030CB044BC5BA59599D7219ED66CC3EA3F898C0CFA5C7E4AFD5EA7220184C9BB79FCE87D74F0D63C8CA6869A0F337C52FFB8E4D7C1968FFADDEB1F5B0D6C83525BC10FBBE1722EAA62C2F6A8A7FF7586EB37CE42B19FEA4C8B8659B0DEF500A0C354851D0514DB5E065010540A9AE6B0E07F4803BE1BB8C7F9D87B6CA9EC0253EE2E34AD75A5C41DA116F16D157EEBA09A467D7C182BB318515A561CCA3F3B9E01F5FAF40EE2B5A8FA3927BC78D3",
                                    16)),
                    8192,
                    new RsaPrivateKey(
                            new BigInteger(
                                    "021b7a7ddf51925505607ee8d2de83704c72cc382f9ed437b99ca36c77adca45d76514a49fafa6d9880a0ce95811ab743f0532672dd24b0b8184a7b456bda6d85b5357949923aed1668f71c6eee2740eca5a8a61fe6667fe7e2f84c199cfeb99223bb1620f1e7e4a547dae7bae39a96fd1b482c40337335bec9b57dedf00c81849115b0ebfa2370d3e8d4d706a8205a1eb63436fd4845794ec11789560aec4da2864d0621006c5534da59f946bc9ba8c89d9d68fe2528c637adfc936c5c01abe5a25c00c16048b80069a20b1c08dff5e2b0631ef6046c626281b7101c5437470e395cd7698a13c273293b09f669b424016fb417f7d99f9a5b337bccfc14b005ec08334de3f1f6e679f7896412aa5f58252085adaca3d123881835f2e4305615770e8377aac44573c36d92f1957c9cd97e14c973222fea7b3806615e2ac4a5583809cdc6223840387515f7937a45c03c01e604d4cb64ad9c3bfa75ffd20732fc2f50e468413d3c4db996d7d90c0f43f1705d980eb813762cb19c051dfb03b127c9f6c833e229efb8bb5359064fbe55a94fb347a52c56cc26b28affb7905650d9b99f6d24795034a1f6de0cb3278bd93f4b5b8c68ed74c6eb6822fd9ffa1dd7f234a72ee97a8fe1f523cc9a04e62a39a9dcf0af90ab5f06dbd3262a6da3dba6cf1eda813234ec5249223d42e2c9b1c5394b6929db4846ac7ea5da6d9f9e3f55321f49784e51ea1a62de517eed9bc8aeca69336f762c07b8139f0b70ad61f818968dc7ec5c0d5774023e6f192ccf9d2b1ef603fb0ddc4e432612e30b09d49e30cdde47647830cd0379ac10e05f41e2e56ead9db737159f8fe32b8d2317c1df33f91d896601df27d1b10a2a9910774157fecd167124cb881bfac97f9192eeb1c4fca1ad6bdc29c2c8699552a3942b37be4bc37706637a80f1105a2b074dbdb5f5aea1c51afb80c01c8da40d600e2730ab2aed3ababf8a07b361f63811cfc54a947029a91be6abe191fd09a4a978044c7694dd701cd247a59d826d5e28d1a6dfae37f7269ae27629509c4220cca4142ee66c2db99726e38911b1f9d095a2094970707270384f2d2b731ca180ffc993a3de32ebb681c35a410b5cffa9cec9e35bb661254742a0190c27016c14c7129c2f433fc896782b85cac8f9cc4afc174503717dc6e7168b417e77eef6fcb33e92a9bd5b4c81e9d262e94a7ea9f238f90cad422c0e878c63c55cd39344edae71de8664f3605e67da9e73e786c2ba44e4583ef3ba9115c51121bb2ad71feba7bb759d345b04b9eee2cf75d4ceb390e713d6f4fd630ff3654e28a73ecece06378521afeff179cfc465d94649634f4034914722d664cce3aed0ba4e10d928cf1787a781251c3c9219b3212c4b4985351110cdd70139cef1de9aa7cd2521c5e5b8d6a95dd14835eed45bfac14fe60f845d26b74d8d701",
                                    16),
                            new BigInteger(
                                    "E62E55E8E10AF1BF05C4638CB49FB4665A115A050D3BAA0CBA2E859782AB7FD7C064B5A2461744C57FD2535E48F74360A10AD8E833D3FF0F99AB3035F3322B860BD174072240D5CBAE70C8B1C6909D8B44D5A5C64EAD6513B40EE895936C1F2B72B30947E4EDD3FA5C2A3A9B9BE122C3E68A70DD015EF717E0F7AB9C88629A0E263F333E96990A026412C4FFFA36AC592E95AF66615A7ED52F19E0C9ED4A0AA2AA3A5BAE41357BC3D405A4B657F50CE9FBE4DE99FA361039B64CD66CC8E85142F0AF04325FD7B007B93D23C9EB69C7C02AD2544C097361AD5603E380F7FD505C2BD0A92151D914AA1FF3B639B2A0CAD0BD292A21BFC5A71D61E4B4B0AF41901BAEEA67051DBAADAD2C767F0AA00DB87071C80EFEC280322A8D99E563ED12ED93BB9659FAC58D70E0765B48C215D2826CC10DDD52DACA897418920A9049D0FBA9DE058B8513B115E6C8DEF8CBC41EC452D3CE5E4CA03D76DE78CCA5C2BF47C52E6DC0ABABAA99E46C7EC221625AE14C7CFCCFB037865A751D3EE63D7189B610EFBFA1907D61C1C71F0AC85D3F45439E027816D6B83669BF1CA1C455C2EE1C967748B6B7A389C230F258D77FAFC294C6F30FFE69A656BAE288EAD1FFC79F33A0C33CAE8639D981D7318A2E8BF39A72E1E1FCEB8E5F2379093A146A576BC48D1656717EA1DEAE45B12FF50B183A932BD0A82C164E2309F0C82B55DA4B68EE9936504995B2E7DEFB7C964A4B09E68EA3860C08D60CD4D5B3A4D427C6FD115FD4AAAA5BCB71D30E1F11354060176B32708067BA58E56787685D9728420C3333A581889FD00D43022849A8326306C332E2344C6AC1F84371956545C1F2D6DA7561F4ACA310383529631D11987362BE63AA67554002ECC98DFA7CC29F800BE49C218B8259CCEE6B8B54987AD6722F2765A339D7D4D396C8EBD83B26558AA84B5C76343DBDA2091022A021FA43F7E37123B4571142F9364CFAB09FC13F9AAE162D95F09AE51052ED3A6E217DEF2D72F1E0F4DD8C1DF760A02498D2D042E86084C7712E4398AF2E26FAEADB14AE78741D72604EAA863CAEBBB93CB4264A115FFDF5E0D6ACB58523E6899620218A677E892FCC1D3A36BC6BE55E7C2E5EA1077261DFE692A793BB18B9115E3B6F80F2FA7A032D089C3DA17FBE9CB7E83859E9F4C48053B45D591FCAEADF26DDAB0CDEE89299BF0C34A1C2E34AD94648150B87B6F8D0E623C7E1FA583F626A23C3C760875708C369354629B4AD819A83D0A0D8CF9B7E006D718C5FF1EE686DBA574755DC17F68582EF9EFB7518207C97E1E1898F0F83D045C617EFED3B356C0FADAA6F0CE501C3657A81FF7E2D7AFA641AB708781966EE48A8643CE8A6697401BEF91EF779A42D102BC435CB20B31BCA90721CF05AF4D5A4E03AB72920DC021A2584FF258726B918F8A1E9E232F2AF21DEA009E0FC9AB79CCD",
                                    16)));

    private List<CipherSuite> rsaKexCipherSuites,
            rsaSigCipherSuites,
            dssCipherSuites,
            dhCipherSuites;
    private Integer minimumRSAKeySize = null;
    private Integer minimumRSASigKeySize = null;
    private Integer minimumDSSKeySize = null;
    private Integer minimumDHKeySize = null;

    public ServerCertificateKeySizeProbe(
            ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.SERVER_CERTIFICATE_MINIMUM_KEY_SIZE, scannerConfig);
        register(
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DSS,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DH,
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA,
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS,
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH);
    }

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA, minimumRSAKeySize);
        put(TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA_SIG, minimumRSASigKeySize);
        put(TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DSS, minimumDSSKeySize);
        put(TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DH, minimumDHKeySize);

        put(
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA,
                resolveResult(minimumRSAKeySize, getSortedKeySizes(RSA_KEYS).getFirst()));
        put(
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                resolveResult(minimumRSASigKeySize, getSortedKeySizes(RSA_KEYS).getFirst()));
        put(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS, TestResults.NOT_TESTED_YET);
        put(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH, TestResults.NOT_TESTED_YET);
    }

    private TestResult resolveResult(Integer determinedKeySize, int ourLowestKeySize) {
        if (determinedKeySize == null) {
            return TestResults.COULD_NOT_TEST;
        } else if (determinedKeySize == ourLowestKeySize) {
            return TestResults.FALSE;
        } else {
            return TestResults.TRUE;
        }
    }

    @Override
    protected void executeTest() {
        if (rsaKexCipherSuites != null && !rsaKexCipherSuites.isEmpty()) {
            LOGGER.debug("Testing RSA key exchange minimum key size");
            minimumRSAKeySize = testRsaKeySize(rsaKexCipherSuites);
        }

        if (rsaSigCipherSuites != null && !rsaSigCipherSuites.isEmpty()) {
            LOGGER.debug("Testing RSA signature minimum key size");
            minimumRSASigKeySize = testRsaKeySize(rsaSigCipherSuites);
        }

        // TODO: Add DSA and DH testing
    }

    /**
     * Test RSA key sizes to find the minimum accepted key size. Uses a linear search approach,
     * testing from smallest to largest.
     *
     * @param cipherSuites List of cipher suites to test with
     * @return The minimum accepted RSA key size in bits, or null if no minimum is enforced
     */
    private Integer testRsaKeySize(List<CipherSuite> cipherSuites) {
        Integer minimumAcceptedSize = null;

        List<Integer> rsaKeySizes = getSortedKeySizes(RSA_KEYS);
        rsaKeySizes.sort(Comparator.naturalOrder());
        for (int keySize : rsaKeySizes) {
            RsaPrivateKey keyMaterial = RSA_KEYS.get(keySize);
            Config config = getRsaConfig(cipherSuites, keyMaterial);
            if (acceptsKeyMaterial(config)) {
                minimumAcceptedSize = keySize;
                LOGGER.debug("First accepted RSA keysize is {} bits", keySize);
                break;
            }
        }
        if (minimumAcceptedSize == null) {
            LOGGER.debug("No RSA key size has been accepted");
        }

        return minimumAcceptedSize;
    }

    private List<Integer> getSortedKeySizes(Map<Integer, ? extends PrivateKeyContainer> keysMap) {
        List<Integer> keySizes = new LinkedList<>(keysMap.keySet());
        keySizes.sort(Comparator.naturalOrder());
        return keySizes;
    }

    /**
     * Test if key material is accepted for the given certificate configuration
     *
     * @param config base config prepared to set a specific key material and cipher suite list
     * @return true if the client accepts the certificate and proceeds with the handshake
     */
    private boolean acceptsKeyMaterial(Config config) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        return trace.executedAsPlanned();
    }

    private Config getRsaConfig(List<CipherSuite> cipherSuites, RsaPrivateKey keyMaterial) {
        Config config = scannerConfig.createConfig();
        config.setDefaultServerSupportedCipherSuites(cipherSuites);
        X509CertificateConfig certConfig = config.getCertificateChainConfig().getFirst();
        certConfig.setDefaultSubjectRsaModulus(keyMaterial.getModulus());
        certConfig.setDefaultSubjectRsaPrivateExponent(keyMaterial.getPrivateExponent());
        certConfig.setDefaultIssuerRsaPublicKey(RSA_PUBLIC_KEY);

        return config;
    }

    @Override
    public void adjustConfig(ClientReport report) {
        dssCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(
                        KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DH_DSS);
        rsaKexCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(KeyExchangeAlgorithm.RSA);
        rsaSigCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(
                        KeyExchangeAlgorithm.DHE_RSA, KeyExchangeAlgorithm.ECDHE_RSA);
        dhCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(
                        KeyExchangeAlgorithm.DH_DSS, KeyExchangeAlgorithm.DH_RSA);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new PropertyTrueRequirement<ClientReport>(TlsAnalyzedProperty.SUPPORTS_RSA)
                .or(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_RSA_SIG))
                .or(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_DSS))
                .or(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_STATIC_DH));
    }
}
