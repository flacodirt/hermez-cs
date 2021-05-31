using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace hermezcs.IntegrationTests
{
    /// <summary>
    /// Keep in sync with UnitTests.BaseTest
    /// </summary>
    public abstract class BaseTest
    {
        // const values from: https://github.com/hermeznetwork/hermezjs/blob/be16cc414640a50adbc9899cefaea8a7ccbc202b/tests/unit/hermez-wallet.test.js
        public const string hermezEthereumAddress = "hez:0x4294cE558F2Eb6ca4C3191AeD502cF0c625AE995";
        public const string hermezEthereumAddressError = "0x4294cE558F2Eb6ca4C3191AeD502cF0c625AE995";
        public byte[] privateKey = new byte[] { 10, 147, 192, 202, 232, 207, 65, 134, 114, 147, 167, 10, 140, 18, 111, 145, 163, 133, 85, 250, 191, 58, 146, 129, 0, 79, 4, 238, 153, 79, 151, 219 };
        public byte[] privateKeyError = new byte[] { 10, 147, 192, 202, 232, 207, 65, 134, 114, 147, 167, 10, 140, 18, 111, 145, 163, 133, 85, 250, 191, 58, 146, 129, 0, 79, 4, 238, 153, 79, 151 };
        public const string expectedSignature = "0x05800968d7d6ffa8368ac363f62ae00213479591e84b7ed07ccbfd40de84cb0d0bb7130748f4d3150d77f1848e1372b84113ba3955a9cefe1bb26b773986d4191b";
        public const string privateKeyEthError = "0x0000000000000000000000000000000000000000000000000000000000000001";
        public const string INTERNAL_ACCOUNT_ETH_ADDR = "hez:0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF";
        public const string EMPTY_BJJ_ADDR = "hez:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        public const string expectedPvtBjj = "6d59205d6117b7185adda0456dd5c018651e98747f9b0754d97f2666313885f6";
        public const string privateKeyEth = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        public const string METAMASK_MESSAGE = "Hermez Network account access.\n\nSign this message if you are in a trusted application only.";
        public const string CREATE_ACCOUNT_AUTH_MESSAGE = "Account creation";
        public const string HERMEZ_PREFIX = "hez:";
        public Regex ethereumAddressPattern = new Regex("^0x[a-fA-F0-9]{40}$");
        public Regex hezEthereumAddressPattern = new Regex("^hez:0x[a-fA-F0-9]{40}$");
        public Regex bjjAddressPattern = new Regex("^hez:[A-Za-z0-9_-]{44}$");
        public Regex signaturePattern = new Regex("^0x[a-fA-F0-9]{130}$");

        // hermezcs
        public byte[] BJJ_DEV_PRIVATE_KEY = Hex.HexToBytes(BJJ_DEV_PRIVATE_KEY_STR);
        public byte[] BJJ_DEV_PUBLIC_KEY;

        public const string ETH_DEV_PRIVATE_KEY_STR = "47f91f3896b5239abcf8c4e21df06e2e640e5cd549404d20182b040b3dd0e3f7";
        public const string ETH_DEV_PUBLIC_ADDRESS = "0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C";
        public const string HEZ_DEV_PUBLIC_ADDRESS = "hez:0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C";

        public const string BJJ_DEV_PRIVATE_KEY_STR = "a563006c8cfd3b2c7f4fa41de10c400f6b9377dde423765fb55c3413400228a2";
        public const string BJJ_DEV_PUBLIC_ADDRESS = "0xe15d1090023d709f87d1C28af7634e0d6BfCb325";
        //public const string BJJ_DEV_PUBLIC_KEY_STR = "27ecb2e541c4685820a2e222e8b09b0bdda4572c8e9e08f1ffdeff2918264cdc46cf06741eb1de678584991a1c87d01c83e926a9606062c7c0bf3ec2b8ede798";

        public const string EXAMPLES_WEB3_URL = "https://rinkeby.infura.io/v3/80496a41d0a134ccbc6e856ffd034696";
        public const string EXAMPLES_HERMEZ_API_URL = "https://api.testnet.hermez.io";
        public const string EXAMPLES_HERMEZ_API_VERSION = "v1";
        public const string EXAMPLES_HERMEZ_ROLLUP_ADDRESS = "0x14a3b6f3328766c7421034e14472f5c14c5ba090";
        public const string EXAMPLES_HERMEZ_WDELAYER_ADDRESS = "0x6ea0abf3ef52d24427043cad3ec26aa4f2c8e8fd";
    }
}
