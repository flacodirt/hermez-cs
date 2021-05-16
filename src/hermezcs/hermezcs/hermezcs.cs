using hermezcs.Abstract;
using hermezcs.Models;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace hermezcs
{
    public class hermezcs : Ihermezcs
    {
        private ILogger<hermezcs> _logger;
        private Ihermezclient _hermezclient;

        public hermezcs(ILogger<hermezcs> logger, Ihermezclient hermezclient, string apiUrl = "https://api.testnet.hermez.io")
        {
            _logger = logger;
            _hermezclient = hermezclient;
            _hermezclient.SetBaseAddress(apiUrl);
        }

        public async Task<List<Token>> GetAvailableTokens()
        {
            var endpoint = "/v1/tokens";
            try
            {
                var httpResponse = await _hermezclient.GetAsync(endpoint);
                httpResponse.EnsureSuccessStatusCode();
                var responseStream = await httpResponse.Content.ReadAsStringAsync();
                var resultResponse = JsonConvert.DeserializeObject<GetAvailableTokensResponse>(responseStream);
                return resultResponse.tokens;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Exception getting accounts. BaseAddress: {_hermezclient.BaseAddress} Endpoint: {endpoint} URI: {_hermezclient.BaseAddress}{endpoint}");
                throw;
            }
        }

        public async Task<List<string>> GetAccounts()
        {
            throw new NotImplementedException();
        }
    }
}
