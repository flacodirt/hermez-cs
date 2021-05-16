using hermezcs.Abstract;
using hermezcs.Models;
using Microsoft.Extensions.Logging;
using Moq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace hermezcs.UnitTests
{
    public class TokenTests
    {
        [Fact]
        public async Task GetAvailableTokens_ShouldReturnListofTokens()
        {
            //arrange
            using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<hermezcs>();
            GetAvailableTokensResponse resp = new GetAvailableTokensResponse
            {
                tokens = new List<Token>
                {
                    new Token
                    {
                        itemId = 1,
                        id = 0,
                        ethereumBlockNum = 0,
                        ethereumAddress = "0x0000000000000000000000000000000000000000",
                        name = "Ether",
                        symbol = "ETH",
                        decimals = 18,
                        USD = 1787,
                        fiatUpdate = DateTime.Parse("2021-02-28T18:55:17.372008Z")
                    },
                    new Token
                    {
                        itemId = 2,
                        id = 1,
                        ethereumBlockNum = 8153596,
                        ethereumAddress = "0x2521bc90b4f5fb9a8d61278197e5ff5cdbc4fbf2",
                        name = "Hermez Network Token",
                        symbol = "HEZ",
                        decimals = 18,
                        USD = 5.365,
                        fiatUpdate = DateTime.Parse("2021-02-28T18:55:17.386805Z")
                    }
                }
            };
            var json = JsonConvert.SerializeObject(resp);
            HttpResponseMessage httpResponse = new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(json)
            };
            var mockHermezclient = new Mock<Ihermezclient>();
            mockHermezclient.Setup(t => t.GetAsync(It.IsAny<string>()))
                .ReturnsAsync(httpResponse);
            var sdk = new hermezcs(logger, mockHermezclient.Object);

            //act
            var tokens = await sdk.GetAvailableTokens();

            //assert
            Assert.True(tokens.Count > 1);
            Assert.Equal("ETH", tokens[0].symbol);
        }
    }
}
