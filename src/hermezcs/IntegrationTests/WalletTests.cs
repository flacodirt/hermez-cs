using System.Text;
using Microsoft.Extensions.Logging;
using Xunit;
using hermezcs.Models;
using Newtonsoft.Json;
using Nethereum.Signer;
using Nethereum.Signer.Crypto;
using Microsoft.AspNetCore.WebUtilities;

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
