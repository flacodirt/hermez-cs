using System.Text;
using Microsoft.Extensions.Logging;
using Xunit;
using hermezcs.Models;
using Newtonsoft.Json;
using Nethereum.Signer;
using Nethereum.Signer.Crypto;
using Microsoft.AspNetCore.WebUtilities;
using Nethereum.Util;
using System.Security.Cryptography;
using System;
using Nethereum.Hex.HexConvertors.Extensions;

namespace hermezcs.IntegrationTests
{
    public class WalletTests : BaseTest
    {
        [Fact]
        public void Crypto_ShouldWork()
        {
            var crypto = new EthECKey(ETH_DEV_PRIVATE_KEY_STR);
            byte[] myPrivateKeyBytes = Hex.HexToBytes(ETH_DEV_PRIVATE_KEY_STR);
            byte[] privateKeyBytes = crypto.GetPrivateKeyAsBytes();
            string privateKey = crypto.GetPrivateKey();                         // "0x47f91f3896b5239abcf8c4e21df06e2e640e5cd549404d20182b040b3dd0e3f7"
            byte[] publicKey = crypto.GetPubKey();
            string publicKeyString = Hex.ToString(publicKey);                   // "042c7a67da7ede9ccb27c514c5111a3625efb283c9ffe33070770242327a49eb72f3a7aafd2c4d20af6ff2264fb9fa29c06e4409a157921f172d571d604df4b006"
            byte[] publicKeyNoPrefix = crypto.GetPubKeyNoPrefix();
            string publicKeyNoPrefixString = Hex.ToString(publicKeyNoPrefix);   // "2c7a67da7ede9ccb27c514c5111a3625efb283c9ffe33070770242327a49eb72f3a7aafd2c4d20af6ff2264fb9fa29c06e4409a157921f172d571d604df4b006"
            string publicAddress = crypto.GetPublicAddress();                   // "0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C"

            Assert.Equal(ETH_DEV_PRIVATE_KEY_STR, privateKey.Substring(2));
            Assert.Equal(myPrivateKeyBytes, privateKeyBytes);
            Assert.Equal(ETH_DEV_PUBLIC_ADDRESS, publicAddress);
            Assert.Matches(ethereumAddressPattern, publicAddress);

            byte[] pubKey = new ECKey(privateKeyBytes, true).GetPubKey(false);
            byte[] pubKeyCompressed = new ECKey(privateKeyBytes, true).GetPubKey(true);
            string pubKeyString = Hex.ToString(pubKey);                         // "042c7a67da7ede9ccb27c514c5111a3625efb283c9ffe33070770242327a49eb72f3a7aafd2c4d20af6ff2264fb9fa29c06e4409a157921f172d571d604df4b006"
            string pubKeyCompressedString = Hex.ToString(pubKeyCompressed);     // "022c7a67da7ede9ccb27c514c5111a3625efb283c9ffe33070770242327a49eb72"

            Assert.Equal(publicKey, pubKey);
            Assert.Equal(publicKeyString, pubKeyString);
            Assert.Equal("02" + (pubKeyString.Substring(2).Substring(0, 64)), pubKeyCompressedString);

            var safeB64Url = WebEncoders.Base64UrlEncode(pubKeyCompressed);                     // "Aix6Z9p-3pzLJ8UUxREaNiXvsoPJ_-MwcHcCQjJ6Sety"
            var final = HERMEZ_PREFIX + safeB64Url;                                             // "hez:Aix6Z9p-3pzLJ8UUxREaNiXvsoPJ_-MwcHcCQjJ6Sety"
            Assert.Matches(bjjAddressPattern, final);
        }

        [Fact]
        public void Compressed_PublicBjjKey_ShouldWork()
        {
            var crypto = new EthECKey(BJJ_DEV_PRIVATE_KEY, true);
            byte[] publicKey = crypto.GetPubKey();                                              // 65 bytes, [0] = 4
            byte[] pubKeyCompressed = new ECKey(BJJ_DEV_PRIVATE_KEY, true).GetPubKey(true);     // 33 bytes, [0] = 2
            var safeB64Url = WebEncoders.Base64UrlEncode(pubKeyCompressed);                     // "AtxMJhgp_97_8QiejixXpN0Lm7DoIuKiIFhoxEHlsuwn"
            var final = HERMEZ_PREFIX + safeB64Url;                                             // "hez:AtxMJhgp_97_8QiejixXpN0Lm7DoIuKiIFhoxEHlsuwn"
            Assert.Matches(bjjAddressPattern, final);

            var a = new Addresses();
            var tb64 = a.HexToBase64BJJ(BJJ_DEV_PRIVATE_KEY);                                     // "hez:AtxMJhgp_97_8QiejixXpN0Lm7DoIuKiIFhoxEHlsuwn"
            Assert.Matches(bjjAddressPattern, tb64);
        }

        [Fact]
        public void Reversing_Compressed_PublicBjjKey_ShouldWork()
        {
            var a = new Addresses();
            var tb64 = a.HexToBase64BJJ(BJJ_DEV_PRIVATE_KEY);                                     // "hez:AtxMJhgp_97_8QiejixXpN0Lm7DoIuKiIFhoxEHlsuwn"
            Assert.Matches(bjjAddressPattern, tb64);

            var rev = a.Base64ToHexBJJ(tb64);
            var compressedPublicKey = new ECKey(BJJ_DEV_PRIVATE_KEY, true).GetPubKey(true);
            Assert.Equal(compressedPublicKey, rev);
        }

        [Fact]
        public void createwalletsignature()
        {
            var signer = new EthereumMessageSigner();
            var key = new EthECKey(ETH_DEV_PRIVATE_KEY_STR); // "47f91f3896b5239abcf8c4e21df06e2e640e5cd549404d20182b040b3dd0e3f7"
            var signature = signer.EncodeUTF8AndSign(CREATE_ACCOUNT_AUTH_MESSAGE, key); // "Account creation"
            Assert.Matches(signaturePattern, signature); // 

            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient(EXAMPLES_HERMEZ_API_URL);
            var sdk = new hermezcs(logger, hermezclient, EXAMPLES_HERMEZ_API_URL, EXAMPLES_HERMEZ_API_VERSION);

            var addy = new Addresses();
            var bjj = addy.HexToBase64BJJ(key.GetPrivateKeyAsBytes());// BJJ_DEV_PRIVATE_KEY);


            var res = sdk.CreateWallet(HEZ_DEV_PUBLIC_ADDRESS, bjj, signature).Result;
        }

        [Fact]
        public void anothertest()
        {
            var privKey = EthECKey.GenerateKey();
            //var privKey = new EthECKey("97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a");
            //var privKey = new EthECKey(ETH_DEV_PRIVATE_KEY_STR);
            byte[] pubKeyCompressed = new ECKey(privKey.GetPrivateKeyAsBytes(), true).GetPubKey(true);
            //Console.WriteLine("Private key: {0}", privKey.GetPrivateKey().Substring(4));
            var myPrivateKeyFull = privKey.GetPrivateKey();
            var myPrivateKeySub  = myPrivateKeyFull.Substring(4);
            //Console.WriteLine("Public key: {0}", privKey.GetPubKey().ToHex().Substring(2));
            var myPublicKeyFull = privKey.GetPubKey();
            var myPublicKeyFullHex = myPublicKeyFull.ToHex();
            var myPublicKeySubHex = myPublicKeyFullHex.Substring(2);
            //Console.WriteLine("Public key (compressed): {0}", pubKeyCompressed.ToHex());
            var myPublicKeyCompressedHex = pubKeyCompressed.ToHex();

            //string msg = "Message for signing";
            var msg = CREATE_ACCOUNT_AUTH_MESSAGE;
            byte[] msgBytes = Encoding.UTF8.GetBytes(msg);
            byte[] msgHash = new Sha3Keccack().CalculateHash(msgBytes);
            var signature = privKey.SignAndCalculateV(msgHash);
            //Console.WriteLine("Msg: {0}", msg);
            //Console.WriteLine("Msg hash: {0}", msgHash.ToHex());
            var myMsgHashHex = msgHash.ToHex();
            //Console.WriteLine("Signature: [v = {0}, r = {1}, s = {2}]",
            //    signature.V[0] - 27, signature.R.ToHex(), signature.S.ToHex());
            var mySignatureV = signature.V[0] - 27;
            var mySignatureRHex = signature.R.ToHex();
            var mySignatureSHex = signature.S.ToHex();

            var pubKeyRecovered = EthECKey.RecoverFromSignature(signature, msgHash);
            //Console.WriteLine("Recovered pubKey: {0}", pubKeyRecovered.GetPubKey().ToHex().Substring(2));
            var myRecPubKeyFull = pubKeyRecovered.GetPubKey();
            var myRecPubKeyFullHex = myRecPubKeyFull.ToHex();
            var myRecPubKeySubHex = myRecPubKeyFullHex.Substring(2);

            bool validSig = pubKeyRecovered.Verify(msgHash, signature);


            //sdk
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient(EXAMPLES_HERMEZ_API_URL);
            var sdk = new hermezcs(logger, hermezclient, EXAMPLES_HERMEZ_API_URL, EXAMPLES_HERMEZ_API_VERSION);


            var encodedB64CompressedPublicKey = WebEncoders.Base64UrlEncode(pubKeyCompressed);
            var bjj = $"{Constants.HERMEZ_PREFIX}{encodedB64CompressedPublicKey}";

            var sig = signature.R.ToHex();
            //var sig = signature.S.ToHex();

            var results = sdk.CreateWallet(HEZ_DEV_PUBLIC_ADDRESS, bjj, sig).Result;
        }

        [Fact]
        public void hwallet_test()
        {
            //https://github.com/hermeznetwork/hermezjs/blob/main/src/hermez-wallet.js
            // /**
            // * Initialize Babyjubjub wallet from private key
            // * @param {Buffer} privateKey - 32 bytes buffer
            // * @param {String} hermezEthereumAddress - Hexadecimal string containing the public Ethereum key from Metamask
            // */
            //constructor (privateKey, hermezEthereumAddress) {
            //  if (privateKey.length !== 32) {
            //    throw new Error('Private key buffer must be 32 bytes')
            //  }

            //  if (!isHermezEthereumAddress(hermezEthereumAddress)) {
            //    throw new Error('Invalid Hermez Ethereum address')
            //  }

            //  const publicKey = circomlib.eddsa.prv2pub(privateKey)
            //  this.privateKey = privateKey
            //  this.publicKey = [publicKey[0].toString(), publicKey[1].toString()]
            //  this.publicKeyHex = [publicKey[0].toString(16), publicKey[1].toString(16)]

            //  const compressedPublicKey = utils.leBuff2int(circomlib.babyJub.packPoint(publicKey))
            //  this.publicKeyCompressed = compressedPublicKey.toString()
            //  this.publicKeyCompressedHex = ethers.utils.hexZeroPad(`0x${compressedPublicKey.toString(16)}`, 32).slice(2)
            //  this.publicKeyBase64 = hexToBase64BJJ(this.publicKeyCompressedHex)

            //  this.hermezEthereumAddress = hermezEthereumAddress


            var privateKey = ETH_DEV_PRIVATE_KEY_STR; // 32 bytes buffer bjj wallet private key
            var hermezEthereumAddress = HEZ_DEV_PUBLIC_ADDRESS; // hexadecimal string public ether key metamask
            //Assert.Equal(32, privateKey.Length);
            var addy = new Addresses();
            Assert.True(addy.IsHermezEthereumAddress(hermezEthereumAddress));

            var privKey = new EthECKey(privateKey);
            byte[] pubKeyCompressed = new ECKey(privKey.GetPrivateKeyAsBytes(), true).GetPubKey(true);
            //Console.WriteLine("Private key: {0}", privKey.GetPrivateKey().Substring(4));
            var myPrivateKeyFull = privKey.GetPrivateKey();
            var myPrivateKeySub = myPrivateKeyFull.Substring(4);
            //Console.WriteLine("Public key: {0}", privKey.GetPubKey().ToHex().Substring(2));
            var myPublicKeyFull = privKey.GetPubKey();
            var myPublicKeyFullHex = myPublicKeyFull.ToHex();
            var myPublicKeySubHex = myPublicKeyFullHex.Substring(2);
            //Console.WriteLine("Public key (compressed): {0}", pubKeyCompressed.ToHex());
            var myPublicKeyCompressedHex = pubKeyCompressed.ToHex();

            var encodedB64CompressedPublicKey = WebEncoders.Base64UrlEncode(pubKeyCompressed);
            var publicKeyBase64 = $"{Constants.HERMEZ_PREFIX}{encodedB64CompressedPublicKey}";


            //string msg = "Message for signing";
            var msg = CREATE_ACCOUNT_AUTH_MESSAGE;
            byte[] msgBytes = Encoding.UTF8.GetBytes(msg);
            byte[] msgHash = new Sha3Keccack().CalculateHash(msgBytes);
            var signature = privKey.SignAndCalculateV(msgHash);
            //Console.WriteLine("Msg: {0}", msg);
            //Console.WriteLine("Msg hash: {0}", msgHash.ToHex());
            var myMsgHashHex = msgHash.ToHex();
            //Console.WriteLine("Signature: [v = {0}, r = {1}, s = {2}]",
            //    signature.V[0] - 27, signature.R.ToHex(), signature.S.ToHex());
            var mySignatureV = signature.V[0] - 27;
            var mySignatureRHex = signature.R.ToHex();
            var mySignatureSHex = signature.S.ToHex();

            var sig = mySignatureRHex;//"{\"Message\":\"checksum verification failed\"}\n"
            //var sig = mySignatureSHex;//"{\"Message\":\"checksum verification failed\"}\n"

            //sdk
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient(EXAMPLES_HERMEZ_API_URL);
            var sdk = new hermezcs(logger, hermezclient, EXAMPLES_HERMEZ_API_URL, EXAMPLES_HERMEZ_API_VERSION);
            var res = sdk.CreateWallet(hermezEthereumAddress, publicKeyBase64, sig).Result;
        }

        //does not work
        ///// <summary>
        ///// https://github.com/hermeznetwork/hermezjs/blob/be16cc414640a50adbc9899cefaea8a7ccbc202b/tests/integration/api.test.js#L302
        ///// </summary>
        //[Fact]
        //public void CreateWallet_UsingExampleKeysFromJs_ShouldVerifySignature()
        //{
        //    //arrange
        //    using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        //    var logger = loggerFactory.CreateLogger<hermezcs>();
        //    var hermezclient = new hermezclient.hermezclient(EXAMPLES_HERMEZ_API_URL);
        //    var sdk = new hermezcs(logger, hermezclient,
        //        EXAMPLES_HERMEZ_API_URL, EXAMPLES_HERMEZ_API_VERSION);

        //    var hermezEthereumAddress = "hez:0x74a549b410d01d9eC56346aE52b8550515B283b2";
        //    var bjjAddress = "hez:dEZ-Tj7d5h0TAqbnRTTYURYDEo5KZzB87_2WknUU8gCN";
        //    var signature = "0x8db6db2ad6cbe21297fb8ee01c59b01b52d4df7ea92a0f0dee0be0075a8f224a06b367407c8f402cfe0490c142a1c92da3fc29b51162ae160d35e1577d3071bb01";

        //    Assert.Matches(hezEthereumAddressPattern, hermezEthereumAddress);
        //    Assert.Matches(bjjAddressPattern, bjjAddress);
        //    Assert.Matches(signaturePattern, signature);

        //    var results = sdk.CreateWallet(hermezEthereumAddress, bjjAddress, signature).Result;
        //    Assert.True(!string.IsNullOrEmpty(results));
        //    Assert.Matches(hezEthereumAddressPattern, results);
        //}

        //item already exists
        ///// <summary>
        ///// https://github.com/hermeznetwork/hermezjs/blob/be16cc414640a50adbc9899cefaea8a7ccbc202b/tests/integration/api.test.js#L302
        ///// </summary>
        //[Fact]
        //public void CreateWallet_UsingWalletKeys_ShouldVerifySignature()
        //{
        //    //arrange
        //    using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        //    var logger = loggerFactory.CreateLogger<hermezcs>();
        //    var hermezclient = new hermezclient.hermezclient(EXAMPLES_HERMEZ_API_URL);
        //    var sdk = new hermezcs(logger, hermezclient,
        //        EXAMPLES_HERMEZ_API_URL, EXAMPLES_HERMEZ_API_VERSION);

        //    var hermezEthereumAddress = "hez:0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C";
        //    var bjjAddress = "hez:IGPlmQcpow-MymlvDVk5crlr4marPHkGcilDdr0vZ6M-";
        //    var signature = "0x5b6060b6b95dc326d26ce8991cdb4015ef5ae8050cb02238df6430165045d22f00104173c941be74b23ff80e6b5ab86938c359eb9c65b9e3782050dd30c0cf4d1c";

        //    Assert.Matches(hezEthereumAddressPattern, hermezEthereumAddress);
        //    Assert.Matches(bjjAddressPattern, bjjAddress);
        //    Assert.Matches(signaturePattern, signature);

        //    var results = sdk.CreateWallet(hermezEthereumAddress, bjjAddress, signature).Result;
        //    Assert.True(!string.IsNullOrEmpty(results));
        //    Assert.Matches(hezEthereumAddressPattern, results);
        //}

        /// <summary>
        /// This only works after connecting the wallet/address to the hermez network
        /// </summary>
        [Fact]
        public void GetAccountCreationAuthorization_ShouldReturnSignature()
        {
            //arrange
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient(EXAMPLES_HERMEZ_API_URL);
            var sdk = new hermezcs(logger, hermezclient,
                EXAMPLES_HERMEZ_API_URL, EXAMPLES_HERMEZ_API_VERSION);
            var results = sdk.GetAuth(HEZ_DEV_PUBLIC_ADDRESS).Result;
            Assert.NotNull(results);
            Assert.Matches(hezEthereumAddressPattern, results.hezEthereumAddress);
            Assert.Equal(HEZ_DEV_PUBLIC_ADDRESS, results.hezEthereumAddress);
            //bjj                 "hez:IGPlmQcpow-MymlvDVk5crlr4marPHkGcilDdr0vZ6M-"
            //hezEthereumAddress  "hez:0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C"
            //signature           "0x5b6060b6b95dc326d26ce8991cdb4015ef5ae8050cb02238df6430165045d22f00104173c941be74b23ff80e6b5ab86938c359eb9c65b9e3782050dd30c0cf4d1c"
            //timestamp           "2021-05-30T03:26:06.727154Z"
        }

        [Fact]
        public void testnew()
        {
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient(EXAMPLES_HERMEZ_API_URL);
            var sdk = new hermezcs(logger, hermezclient,
                EXAMPLES_HERMEZ_API_URL, EXAMPLES_HERMEZ_API_VERSION);

            var testPrivKey = "e2ad989d49049e754a2931403e7e5650aa4791c3c50d9f83fa4cc221b61e7a8f";
            var testEthPubAddy = "0xa903E948381c4841e7D8906f60ec587221A3b305";
            var testHezPubAddy = $"{HERMEZ_PREFIX}{testEthPubAddy}";
            var msgToSign = "Hermez Network account access.\n\nSign this message if you are in a trusted application only.";
            Assert.Matches(ethereumAddressPattern, testEthPubAddy);

            var ethEcKey = new EthECKey(testPrivKey);
            var testPrivKeyBytes = ethEcKey.GetPrivateKeyAsBytes();
            using (var sha256 = SHA256.Create())
            {
                //var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(msgToSign));
                var addresses = new Addresses();
                var bjjPubComp = addresses.HexToBase64BJJ(testPrivKeyBytes);
                Assert.Matches(bjjAddressPattern, bjjPubComp);

                var signer = new EthereumMessageSigner();

                //checksum verification failed
                var sig1 = signer.EncodeUTF8AndSign(msgToSign, ethEcKey);
                Assert.Matches(signaturePattern, sig1);
                var results = sdk.CreateWallet(testHezPubAddy, bjjPubComp, sig1).Result;
                Assert.True(!string.IsNullOrEmpty(results));
            }
        }

        /// <summary>
        /// https://docs.ethers.io/v4/api-wallet.html
        /// </summary>
        [Fact]
        public void EthMsgSigner_EncodeUTF8AndSignMsg_ShouldWork()
        {
            var privKey = "0x3141592653589793238462643383279502884197169399375105820974944592";
            var ethEcKey = new EthECKey(privKey);
            var msg = "Hello World!";
            var signer = new EthereumMessageSigner();
            var sig1 = signer.EncodeUTF8AndSign(msg, ethEcKey);
            Assert.Matches(signaturePattern, sig1);
            Assert.Equal("0xea09d6e94e52b48489bd66754c9c02a772f029d4a2f136bba9917ab3042a0474301198d8c2afb71351753436b7e5a420745fed77b6c3089bbcca64113575ec3c1c",
                sig1);
        }

        /// <summary>
        /// https://docs.ethers.io/v4/api-wallet.html
        /// </summary>
        [Fact]
        public void EthMsgSigner_Binary_ShouldWork()
        {
            var privKey = "0x3141592653589793238462643383279502884197169399375105820974944592";
            var ethEcKey = new EthECKey(privKey);
            var msg = "0x3ea2f1d0abf3fc66cf29eebb70cbd4e7fe762ef8a09bcc06c8edf641230afec0";
            var signer = new EthereumMessageSigner();
            var sig1 = signer.Sign(Hex.HexToBytes(msg), ethEcKey);
            Assert.Matches(signaturePattern, sig1);
            Assert.Equal("0x5e9b7a7bd77ac21372939d386342ae58081a33bf53479152c87c1e787c27d06b118d3eccff0ace49891e192049e16b5210047068384772ba1fdb33bbcba580391c",
                sig1);
        }

        [Fact]
        public void Test_createWalletFromEtherAccount()
        {
            //arrange
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient(EXAMPLES_HERMEZ_API_URL);
            var sdk = new hermezcs(logger, hermezclient,
                EXAMPLES_HERMEZ_API_URL, EXAMPLES_HERMEZ_API_VERSION);

            // construct request
            var addresses = new Addresses();
            var bjjPubComp = addresses.HexToBase64BJJ(BJJ_DEV_PRIVATE_KEY);                     // "hez:AtxMJhgp_97_8QiejixXpN0Lm7DoIuKiIFhoxEHlsuwn"

            var ethEcKey = new EthECKey(ETH_DEV_PRIVATE_KEY_STR);
            var pubAddy = ethEcKey.GetPublicAddress();                                          //+"0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C"

            // sign message with ETH privatekey
            var signer = new EthereumMessageSigner();
            var msgBytes = Encoding.UTF8.GetBytes(CREATE_ACCOUNT_AUTH_MESSAGE);

            // V1: Hash in, hash out
            var signatureV1 = signer.HashAndSign(CREATE_ACCOUNT_AUTH_MESSAGE, ETH_DEV_PRIVATE_KEY_STR);    // "0xaa65ff538b3893fa6edc06faa84bba987149fe5234bfa3cebbe599d4dd7917190aec05d4dcf62c4edf3c66e8fa8b2c810c71717fc49d628a148b61faecbc53731c"
            var recPubAddyV1 = signer.HashAndEcRecover(CREATE_ACCOUNT_AUTH_MESSAGE, signatureV1);          //+"0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C"
            Assert.Equal(pubAddy, recPubAddyV1);

            // V2: Encoded in, encoded out
            var signatureV2 = signer.Sign(msgBytes, ethEcKey);                                             // "0x4eb7b6fa50c4dec29106c8fea1e1cb852c79b1014b372545a334038b03970b1641b1812afb99cf734e02cf2ce7aab1e28ca08e2f7bb6cc91747f09e742d13d4b1c"
            var signatureV3 = signer.EncodeUTF8AndSign(CREATE_ACCOUNT_AUTH_MESSAGE, ethEcKey);             // "0x4eb7b6fa50c4dec29106c8fea1e1cb852c79b1014b372545a334038b03970b1641b1812afb99cf734e02cf2ce7aab1e28ca08e2f7bb6cc91747f09e742d13d4b1c"
            //Assert.Equal(signatureV1, signatureV2);
            Assert.Equal(signatureV2, signatureV3);

            // V4:
            //var signatureV4 = signer.HashAndHashPrefixedMessage(msgBytes);

            //var sig = signatureV1;
            //var sig = signatureV2;
            var sig = signatureV3;

            var req = new CreateWalletRequest
            {
                hezEthereumAddress = HEZ_DEV_PUBLIC_ADDRESS,
                bjj = bjjPubComp,
                signature = sig
            };
            Assert.Matches(hezEthereumAddressPattern, req.hezEthereumAddress);
            Assert.Matches(bjjAddressPattern, req.bjj);
            var messageContentString = JsonConvert.SerializeObject(req, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
            var resultsC = sdk.CreateWallet(req.hezEthereumAddress, req.bjj, req.signature).Result;
            Assert.True(!string.IsNullOrEmpty(resultsC));
            Assert.Matches(hezEthereumAddressPattern, resultsC);


            //{
            //    "hezEthereumAddress":"hez:0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C",
            //    "bjj":"hez:AtxMJhgp_97_8QiejixXpN0Lm7DoIuKiIFhoxEHlsuwn",
            //    "signature":"0x60e2a2a6537aaec7cc9c3b4e5b02e1e8cf98d04549ca9f696d00a1792088a8dc17890321145c1d04a4e3b471f3e785d319b507e627c5e0d897e08e86af6a7bd81b"
            //}



            ////compresed public key
            //var ecKey = new ECKey(privateKey, true);//.GetPubKey(true);
            //var compressedPubKey = ecKey.GetPubKey(true);
            //var bjj = $"{HERMEZ_PREFIX}{Hex.ToString(compressedPubKey)}";

            //"hez:0x4294cE558F2Eb6ca4C3191AeD502cF0c625AE995"
            //"hez:02598aa073403c74421d14203154e84103713f12609f55aae2b00dbf80d14a34fa"
            //"0x2db24931e461f82510b280a04cdd3f7a24c8c4362d854ef2d0f4acde503f392408d36b4216f9b4daf668320e75b437d0e7d90d8c6d0bab4f107323d69e42e87f1c"
            //"0x0afdf08cc75e19a9e195a8b96b27d90b784bb6de204beab173c07c50e1fb27180263b6d9e1b86f730255c8e0e2337fe01a5ef6219fd64703ebfb126428afc0001b"
            //var resultsC = sdk.CreateWallet(hermezEthereumAddress, bjj, signatureV1).Result;




            //"{\"Message\":\"invalid BJJ format. Must follow this regex: ^hez:[A-Za-z0-9_-]{44}$\"}\n"


            //using (var crypto = new crypto())
            //{
            //    //var publicKeyCompressedHexBytes = crypto.GetCompressedPublicKey(privateKey);
            //    //var publicKeyCompressedHexString = Hex.ToString(publicKeyCompressedHexBytes);

            //    // https://github.com/hermeznetwork/hermezjs/blob/be16cc414640a50adbc9899cefaea8a7ccbc202b/src/hermez-wallet.js#L70
            //    // const bJJ = this.publicKeyCompressedHex.startsWith('0x')
            //    //  ? this.publicKeyCompressedHex
            //    //  : `0x${this.publicKeyCompressedHex}`
            //    // this doesnt pass regex starting with hez: ...
            //    //var bjj = publicKeyCompressedHexString.StartsWith("0x")
            //    //            ? publicKeyCompressedHexString
            //    //            : $"0x{publicKeyCompressedHexString}";

            //    var bjj = $"{HERMEZ_PREFIX}{crypto.GetEncodedCompressedPublicKey(privateKey)}";

            //    // https://github.com/hermeznetwork/hermezjs/blob/be16cc414640a50adbc9899cefaea8a7ccbc202b/src/hermez-wallet.js#L101
            //    //const hermezEthereumAddress = getHermezAddress(ethereumAddress)
            //    //const signature = await signer.signMessage(METAMASK_MESSAGE)
            //    var signature = crypto.SignMessage(
            //        Encoding.UTF8.GetBytes("Hermez Network account access.\n\nSign this message if you are in a trusted application only."),
            //        privateKey);

            //    var ethEckey = new EthECKey(privateKey, true);

            //    var hashedData = Sha3Keccack.Current.CalculateHash("Test");
            //    var correctSignature = ethEckey.SignAndCalculateV(hashedData);


            //    //const hashedSignature = jsSha3.keccak256(signature)
            //    //const bufferSignature = hexToBuffer(hashedSignature)
            //    Assert.Matches(hezEthereumAddressPattern, hermezEthereumAddress);
            //    Assert.Matches(bjjAddressPattern, bjj);
            //    Assert.Matches(signaturePattern, signature);

            //    //const hermezWallet = new HermezWallet(bufferSignature, hermezEthereumAddress)
            //    var resultsC = sdk.CreateWallet(hermezEthereumAddress, bjj, signature).Result;
            //    Assert.True(!string.IsNullOrEmpty(resultsC));
            //    Assert.Matches(hezEthereumAddressPattern, resultsC);
            //}
        }

        [Fact]
        public void CreateWallet_ShouldReturnNewWalletAddress()
        {
            //arrange
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient(EXAMPLES_HERMEZ_API_URL);
            var sdk = new hermezcs(logger, hermezclient,
                EXAMPLES_HERMEZ_API_URL, EXAMPLES_HERMEZ_API_VERSION);

            // new request
            using (var crypto = new crypto())
            {
                // construct request
                var req = new CreateWalletRequest
                {
                    hezEthereumAddress = $"{HERMEZ_PREFIX}{ETH_DEV_PUBLIC_ADDRESS}",
                    bjj = $"{HERMEZ_PREFIX}{crypto.GetEncodedCompressedPublicKey(BJJ_DEV_PRIVATE_KEY)}"
                };
                Assert.Matches(hezEthereumAddressPattern, req.hezEthereumAddress);
                Assert.Matches(bjjAddressPattern, req.bjj);

                // serialize request object to string
                var messageContentString = JsonConvert.SerializeObject(req, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
                //"{\"hezEthereumAddress\":\"hez:0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C\",\"bjj\":\"hez:AtxMJhgp_97_8QiejixXpN0Lm7DoIuKiIFhoxEHlsuwn\",\"signature\":null}"
                //"{\"hezEthereumAddress\":\"hez:0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C\",\"bjj\":\"hez:AtxMJhgp_97_8QiejixXpN0Lm7DoIuKiIFhoxEHlsuwn\"}"

                // sign msg with ETH KEY
                var signer = new EthereumMessageSigner();
                var signature1 = signer.EncodeUTF8AndSign(messageContentString, new EthECKey(ETH_DEV_PRIVATE_KEY_STR));
                //"0x5197eaa011b34c273ab34d4d8dd7df644924d56e378553d1911f99a825f3f81b10e44cbe0e5113794e1d0e718af50c2db15b878972de3a9bfa3fac237a9a41471b"
                //var signature2 = signer.HashAndSign(messageContentString, ETH_DEV_PRIVATE_KEY_STR);
                //"0xa84217e9fffa1844f45c4dbaaa274d5d898bf97db9557ac8caf299829c771dd13017a2055da19b87b29834e4b6575be976ffcf180c250c2a840a5d0e9a26be9d1b"
                //var signature3 = signer.Sign(Encoding.UTF8.GetBytes(messageContentString), ETH_DEV_PRIVATE_KEY_STR);
                //"0x5197eaa011b34c273ab34d4d8dd7df644924d56e378553d1911f99a825f3f81b10e44cbe0e5113794e1d0e718af50c2db15b878972de3a9bfa3fac237a9a41471b"

                var signature = signature1;
                req.signature = signature;
                Assert.Matches(signaturePattern, req.signature);

                //var resultsA = sdk.CreateWallet(req.hezEthereumAddress, req.bjj, signature1).Result;
                //var resultsB = sdk.CreateWallet(req.hezEthereumAddress, req.bjj, signature2).Result;
                var resultsC = sdk.CreateWallet(req.hezEthereumAddress, req.bjj, signature1).Result;

                //verify?
                //var addressRec = signer.EncodeUTF8AndEcRecover(messageContentString, signature);
                //"0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C"
                //var signer2 = new MessageSigner();
                //var hash = signer.Hash(Encoding.UTF8.GetBytes(messageContentString));
                //"0x5197eaa011b34c273ab34d4d8dd7df644924d56e378553d1911f99a825f3f81b10e44cbe0e5113794e1d0e718af50c2db15b878972de3a9bfa3fac237a9a41471b"
                //"0x55c2750761c822c9b2f8598fe3d884e3c3efef5f80a589f615cffcf7d9700e0c0c57570c2e2bfd93dfb3c948f3317d0280161dac9407063fb300e2db78e18e321c"
                //"0xa84217e9fffa1844f45c4dbaaa274d5d898bf97db9557ac8caf299829c771dd13017a2055da19b87b29834e4b6575be976ffcf180c250c2a840a5d0e9a26be9d1b"
                //"0xefc79de025e6caccd9acfdf46c5022250538273f0a10e65d02164fbdbc3bb8af0db8407076342ae2c8acd9f54077a5ced657120ae440d1d1e23b6a8b868dfd1c1b"
                // verify
                //var signatureVer1 = MessageSigner.ExtractEcdsaSignature(signature);
                //var signatureVer2 = MessageSigner.ExtractEcdsaSignature(signature2);
                //var verify1 = eck.Verify(hash, signature);
                //var verify2 = etheckey.Verify(hash, signatureVer); // true
                //var messageContentStringAsBytes = Hex.HexToBytes(messageContentString);
                //req.signature = crypto.SignMessage(messageContentStringAsBytes, r.PrivateKeyBytes);
                //Assert.Matches(signaturePattern, req.signature);
                //var test1 = signer.EcRecover(messageContentStringAsBytes, req.signature);

                //var results = sdk.CreateWallet(req.hezEthereumAddress, req.bjj, req.signature).Result;

                Assert.True(!string.IsNullOrEmpty(resultsC));
                Assert.Matches(hezEthereumAddressPattern, resultsC);

            }

        }
    }
}
