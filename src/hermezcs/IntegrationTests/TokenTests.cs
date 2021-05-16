using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using Xunit;

namespace hermezcs.IntegrationTests
{
    public class TokenTests
    {
        [Fact]
        public async Task GetAvailableTokens_ShouldReturnListofTokens()
        {
            //arrange
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            //var apiUrl = "https://apimock.hermez.network";
            var apiUrl = "https://api.testnet.hermez.io";
            var hermezclient = new hermezclient.hermezclient(apiUrl);
            var sdk = new hermezcs(logger, hermezclient);

            //act
            var tokens = await sdk.GetAvailableTokens();

            //assert
            Assert.True(tokens.Count > 1);
        }
    }
}
