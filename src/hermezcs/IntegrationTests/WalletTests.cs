using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using Xunit;

namespace hermezcs.IntegrationTests
{
    public class WalletTests
    {
        private const string ETH_DEV_PRIVATE_KEY = "47f91f3896b5239abcf8c4e21df06e2e640e5cd549404d20182b040b3dd0e3f7";

        private const string EXAMPLES_WEB3_URL = "https://rinkeby.infura.io/v3/80496a41d0a134ccbc6e856ffd034696";
        private const string EXAMPLES_HERMEZ_API_URL = "https://api.testnet.hermez.io";
        private const string EXAMPLES_HERMEZ_ROLLUP_ADDRESS = "0x14a3b6f3328766c7421034e14472f5c14c5ba090";
        private const string EXAMPLES_HERMEZ_WDELAYER_ADDRESS = "0x6ea0abf3ef52d24427043cad3ec26aa4f2c8e8fd";

        [Fact]
        public async Task CreateWallet_ShouldReturnNewWalletAddress()
        {

        }
    }
}
