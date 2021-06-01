using Microsoft.Extensions.Logging;
using Xunit;
using Nethereum.Signer;
using Nethereum.Signer.Crypto;
using Nethereum.Hex.HexConvertors.Extensions;
using System.Text.RegularExpressions;
using System.Text;

namespace hermezcs.IntegrationTests
{
    public class HermezNetworkTests
    {
        public const string MyTestPrivateKey = "47f91f3896b5239abcf8c4e21df06e2e640e5cd549404d20182b040b3dd0e3f7";
        public const string MyExpectedPublicAddress = "0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C";
        public const string MyExpectedHezPublicAddress = "hez:0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C";
        public const string MyMessage = "Account creation";
        public Regex EthereumAddressPattern = new Regex("^0x[a-fA-F0-9]{40}$");
        public Regex HezEthereumAddressPattern = new Regex("^hez:0x[a-fA-F0-9]{40}$");
        public Regex BjjAddressPattern = new Regex("^hez:[A-Za-z0-9_-]{44}$");
        public Regex SignaturePattern = new Regex("^0x[a-fA-F0-9]{130}$");

        #region Helper Methods

        /// <summary>
        /// Both tests are using this method to obtain the signature
        /// </summary>
        /// <param name="privateKeyString"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        private string GetSignature(string privateKeyString, string message)
        {
            var ethEcKey = new EthECKey(privateKeyString);
            var signer = new EthereumMessageSigner();
            return signer.EncodeUTF8AndSign(message, ethEcKey);
        }

        /// <summary>
        /// Method used to recover the public address from a signed message
        /// </summary>
        /// <param name="message"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        private string RecoverPublicAddressFromSignedMessage(string message, string signature)
        {
            var signer = new EthereumMessageSigner();
            return signer.EncodeUTF8AndEcRecover(message, signature);
        }

        #endregion

        /// <summary>
        /// This test is passing, able to recover the public address from a message and its signature
        /// This is using the same signing method that is getting 'invalid signature' error when posted to hermez api
        /// </summary>
        [Fact]
        public void Signature_ShouldVerify()
        {
            var signature = GetSignature(MyTestPrivateKey, MyMessage); // "0x4eb7b6fa50c4dec29106c8fea1e1cb852c79b1014b372545a334038b03970b1641b1812afb99cf734e02cf2ce7aab1e28ca08e2f7bb6cc91747f09e742d13d4b1c"
            Assert.Matches(SignaturePattern, signature);

            var recovered = RecoverPublicAddressFromSignedMessage(MyMessage, signature);
            Assert.Equal(MyExpectedPublicAddress, recovered);
        }

        /// <summary>
        /// This test is failing with error 'invalid signature'
        /// Even though the test above is able to verify the same signature method
        /// </summary>
        [Fact]
        public void PostToCreateWallet_WithB64BjjPubKeyCompressedHexCompact_ShouldWork()
        {
            //bjj
            var ethEcKey = new EthECKey(MyTestPrivateKey);
            var pubKeyCompressedBytes = new ECKey(ethEcKey.GetPrivateKeyAsBytes(), true).GetPubKey(true); // 33 bytes
            var hexCompact = pubKeyCompressedBytes.ToHexCompact();      // "22c7a67da7ede9ccb27c514c5111a3625efb283c9ffe33070770242327a49eb72"
            var addresses = new Addresses();
            var b64bjj = addresses.HexToBase64BJJ(hexCompact);          // "hez:Aix6Z9p-3pzLJ8UUxREaNiXvsoPJ_-MwcHcCQjJ6SesB"
            Assert.Matches(BjjAddressPattern, b64bjj);

            // sign msg
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(MyMessage, ethEcKey);
            Assert.Matches(SignaturePattern, signature);

            //sdk post to create wallet
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            var hermezclient = new hermezclient.hermezclient();
            var sdk = new hermezcs(logger, hermezclient);
            var results = sdk.CreateWallet(MyExpectedHezPublicAddress, b64bjj, signature).Result;

            //fixed checksum error by changing how b64bjj was generated to include the sum byte replacement
            //sum ^= pubKeyCompressed[i];           // "checksum verification failed"

            //now getting invalid signature error
            //sum = (int)Math.Pow((sum % 2), 8);    // "invalid signature"
        }

    }
}
