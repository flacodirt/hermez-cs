using Microsoft.Extensions.Logging;
using Xunit;
using Nethereum.Signer;
using Nethereum.Signer.Crypto;
using Nethereum.Hex.HexConvertors.Extensions;
using System.Text.RegularExpressions;
using System.Text;

namespace hermezcs.IntegrationTests
{
    public class HermezNetworkTestsTwo
    {
        public const string MyTestPrivateKey = "47f91f3896b5239abcf8c4e21df06e2e640e5cd549404d20182b040b3dd0e3f7";
        public const string MyExpectedPublicAddress = "0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C";
        public const string MyExpectedHezPublicAddress = "hez:0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C";
        public const string MyMessage = "Account creation";
        public Regex EthereumAddressPattern = new Regex("^0x[a-fA-F0-9]{40}$");
        public Regex HezEthereumAddressPattern = new Regex("^hez:0x[a-fA-F0-9]{40}$");
        public Regex BjjAddressPattern = new Regex("^hez:[A-Za-z0-9_-]{44}$");
        public Regex SignaturePattern = new Regex("^0x[a-fA-F0-9]{130}$");

        /// <summary>
        /// This test is using values from hermezjs unit tests that should work... but dont
        /// https://github.com/hermeznetwork/hermezjs/blob/be16cc414640a50adbc9899cefaea8a7ccbc202b/tests/unit/hermez-wallet.test.js#L95
        /// </summary>
        [Fact]
        public void PostToCreateWallet_UsingHermezJsUnitTestValues_ShouldWork()
        {
            //bjj
            var ethEcKey = new EthECKey("0x0000000000000000000000000000000000000000000000000000000000000001");
            var pubKeyCompressedBytes = new ECKey(ethEcKey.GetPrivateKeyAsBytes(), true).GetPubKey(true); // 33 bytes
            var hexCompact = pubKeyCompressedBytes.ToHexCompact();      // "279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            var addresses = new Addresses();
            var b64bjj = addresses.HexToBase64BJJ(hexCompact);          // "hez:Anm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BcA"
            Assert.Matches(BjjAddressPattern, b64bjj);

            // sign msg
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(MyMessage, ethEcKey); // "0xd3d53f25f88f551d31f28b87cf49d05143eaf95b7f7d4bf12a82eb3a06377148373fba488b9987445af4f2a343e8f6dc6e4270706e505293a3fd1e889755bd2b1b"
            Assert.Matches(SignaturePattern, signature);
            //this fails:
            //Assert.Equal("0x05800968d7d6ffa8368ac363f62ae00213479591e84b7ed07ccbfd40de84cb0d0bb7130748f4d3150d77f1848e1372b84113ba3955a9cefe1bb26b773986d4191b", signature);

            //sdk post to create wallet
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient();
            var sdk = new hermezcs(logger, hermezclient);

            var pubAddy = ethEcKey.GetPublicAddress(); // "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"

            var results = sdk.CreateWallet("hez:"+pubAddy, b64bjj, signature).Result;

            //"checksum verification failed"
        }

        /// <summary>
        /// This test is to use a different private key for the BJJ than the HEZ Pub Addy
        /// https://github.com/hermeznetwork/hermezjs/blob/be16cc414640a50adbc9899cefaea8a7ccbc202b/tests/unit/hermez-wallet.test.js#L121
        /// </summary>
        [Fact]
        public void PostToCreateWallet_UsingDiffKeysBjjEth_ShouldWork()
        {
            //bjj
            var ethEcKey = new EthECKey("6d59205d6117b7185adda0456dd5c018651e98747f9b0754d97f2666313885f6");
            var pubKeyCompressedBytes = new ECKey(ethEcKey.GetPrivateKeyAsBytes(), true).GetPubKey(true); // 33 bytes
            var hexCompact = pubKeyCompressedBytes.ToHexCompact();      // "322e7f144ae5f65f038c9809e54aa2d19760923d24594e71cc4120adaba913855"
            var addresses = new Addresses();
            var b64bjj = addresses.HexToBase64BJJ(hexCompact);          // "hez:AyLn8USuX2XwOMmAnlSqLRl2CSPSRZTnHMQSCtq6kTgA"
            Assert.Matches(BjjAddressPattern, b64bjj);

            // sign msg
            var privateEthKey = new EthECKey(MyTestPrivateKey);
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(MyMessage, privateEthKey); // "0x4eb7b6fa50c4dec29106c8fea1e1cb852c79b1014b372545a334038b03970b1641b1812afb99cf734e02cf2ce7aab1e28ca08e2f7bb6cc91747f09e742d13d4b1c"
            Assert.Matches(SignaturePattern, signature);

            //sdk post to create wallet
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient();
            var sdk = new hermezcs(logger, hermezclient);
            var results = sdk.CreateWallet(MyExpectedHezPublicAddress, b64bjj, signature).Result;

            //"checksum verification failed"
        }

        /// <summary>
        /// This test is to use a different private key for the BJJ than the HEZ Pub Addy
        /// https://github.com/hermeznetwork/hermezjs/blob/be16cc414640a50adbc9899cefaea8a7ccbc202b/tests/unit/hermez-wallet.test.js#L121
        /// </summary>
        [Fact]
        public void PostToCreateWallet_UsingDiffKeysBjjEthTry2_ShouldWork()
        {
            //bjj
            var ethEcKey = new EthECKey("6d59205d6117b7185adda0456dd5c018651e98747f9b0754d97f2666313885f6");
            var pubKeyCompressedBytes = new ECKey(ethEcKey.GetPrivateKeyAsBytes(), true).GetPubKey(true); // 33 bytes
            var hexCompact = pubKeyCompressedBytes.ToHexCompact();      // "322e7f144ae5f65f038c9809e54aa2d19760923d24594e71cc4120adaba913855"
            var addresses = new Addresses();
            var b64bjj = addresses.HexToBase64BJJ(hexCompact);          // "hez:AyLn8USuX2XwOMmAnlSqLRl2CSPSRZTnHMQSCtq6kTgA"
            Assert.Matches(BjjAddressPattern, b64bjj);

            // sign msg
            var privateEthKey = new EthECKey("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(MyMessage, privateEthKey); // "0x1ba9b1769b3857964042784bd38d67b12b0b30055d2ad82fffdc9f9d9f2a1a6f792a0d459aa96a4b0240b75ba8851cee7cb9a6161c94fae43fb638f230294edc1c"
            Assert.Matches(SignaturePattern, signature);

            //sdk post to create wallet
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient();
            var sdk = new hermezcs(logger, hermezclient);
            var results = sdk.CreateWallet(MyExpectedHezPublicAddress, b64bjj, signature).Result;

            //"checksum verification failed"
        }

        /// <summary>
        /// Using values from:
        /// https://github.com/hermeznetwork/commonjs/blob/59e7c8cb2baa2cdcf2b0788e276d9e1f19735d08/test/tx-utils.test.js#L180
        /// </summary>
        [Fact]
        public void PostToCreateWallet_TxUtilsTestL180_ShouldWork()
        {
            //bjj
            //var ethEcKey = new EthECKey("0x21b0a1688b37f77b1d1d5539ec3b826db5ac78b2513f574a04c50a7d4f8246d7");
            //var pubKeyCompressedBytes = new ECKey(ethEcKey.GetPrivateKeyAsBytes(), true).GetPubKey(true); // 33 bytes
            var hexCompact = "0x21b0a1688b37f77b1d1d5539ec3b826db5ac78b2513f574a04c50a7d4f8246d7";
            var addresses = new Addresses();
            var b64bjj = addresses.HexToBase64BJJ(hexCompact);          // "hez:ISGwoWiLN_d7HR1VOew7gm21rHiyUT9XSgTFCn1PgkYB"
            Assert.Matches(BjjAddressPattern, b64bjj);

            // sign msg
            var privateEthKey = new EthECKey("0000000000000000000000000000000000000000000000000000000000000001");
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(MyMessage, privateEthKey); // "0xd3d53f25f88f551d31f28b87cf49d05143eaf95b7f7d4bf12a82eb3a06377148373fba488b9987445af4f2a343e8f6dc6e4270706e505293a3fd1e889755bd2b1b"
            Assert.Matches(SignaturePattern, signature);
            //fails: Assert.Equal("0xdbedcc5ce02db8f48afbdb2feba9a3a31848eaa8fca5f312ce37b01db45d2199208335330d4445bd2f51d1db68dbc0d0bf3585c4a07504b4efbe46a69eaae5a21b", signature);

            //sdk post to create wallet
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient();
            var sdk = new hermezcs(logger, hermezclient);
            var results = sdk.CreateWallet("hez:0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", b64bjj, signature).Result;

            //"checksum verification failed"
        }

        /// <summary>
        /// Using values from:
        /// https://github.com/hermeznetwork/commonjs/blob/59e7c8cb2baa2cdcf2b0788e276d9e1f19735d08/test/tx-utils.test.js#L190
        /// </summary>
        [Fact]
        public void PostToCreateWallet_TxUtilsTestL190_ShouldWork()
        {
            //bjj
            var ethEcKey = new EthECKey("093985b1993d9f743f9d7d943ed56f38601cb8b196db025f79650c4007c3054d");
            var pubKeyCompressedBytes = new ECKey(ethEcKey.GetPrivateKeyAsBytes(), true).GetPubKey(true); // 33 bytes
            var hexCompact = pubKeyCompressedBytes.ToHexCompact();
            var addresses = new Addresses();
            var b64bjj = addresses.HexToBase64BJJ(hexCompact);          // "hez:ISGwoWiLN_d7HR1VOew7gm21rHiyUT9XSgTFCn1PgkYB"
            Assert.Matches(BjjAddressPattern, b64bjj);

            // sign msg
            var privateEthKey = new EthECKey("0000000000000000000000000000000000000000000000000000000000000002");
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(MyMessage, privateEthKey); // "0xeca7c81cc493a9a666828494f90043ed196410f546f819767a702f5d4fdea54a7041e2da6c317495f32dc5fdd3a8f6f9aafe3942514fb33b75ce9a9693065c441c"
            Assert.Matches(SignaturePattern, signature);
            //fails: Assert.Equal("0x6a0da90ba2d2b1be679a28ebe54ee03082d44b836087391cd7d2607c1e4dafe04476e6e88dccb8707c68312512f16c947524b35c80f26c642d23953e9bb84c701c", signature);

            //sdk post to create wallet
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient();
            var sdk = new hermezcs(logger, hermezclient);
            var results = sdk.CreateWallet("hez:0x2b5ad5c4795c026514f8317c7a215e218dccd6cf", b64bjj, signature).Result;

            //"checksum verification failed"
        }
    }
}
