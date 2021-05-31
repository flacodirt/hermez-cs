using hermezcs.Abstract;
using hermezcs.Models;
using hermezcs.Models.hermez;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Secp256k1Net;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace hermezcs
{
    public class hermezcs : Ihermezcs
    {
        private ILogger<hermezcs> _logger;
        private Ihermezclient _hermezclient;
        private string _apiVersion;

        public hermezcs(ILogger<hermezcs> logger, Ihermezclient hermezclient,
            string apiUrl = "https://api.testnet.hermez.io",
            string apiVersion = "v1")
        {
            _logger = logger;
            _hermezclient = hermezclient;
            _hermezclient.SetBaseAddress(apiUrl);
            _apiVersion = apiVersion;
        }

        private void HandleErrorResponse(HttpResponseMessage httpResponse, string responseStream)
        {
            // log error response
            var errorResultResponse = JsonConvert.DeserializeObject<ErrorResponse>(responseStream);
            _logger.LogError($"hermez network non-success status code: ({(int)httpResponse.StatusCode}) {httpResponse.StatusCode}, response: {errorResultResponse.message}");
            // throw exception if not success
            httpResponse.EnsureSuccessStatusCode();
        }

        public async Task<List<Token>> GetAvailableTokens()
        {
            var endpoint = $"/{_apiVersion}/tokens";
            try
            {
                var httpResponse = await _hermezclient.GetAsync(endpoint);
                var responseStream = await httpResponse.Content.ReadAsStringAsync();
                if (!httpResponse.IsSuccessStatusCode) HandleErrorResponse(httpResponse, responseStream);
                var resultResponse = JsonConvert.DeserializeObject<GetAvailableTokensResponse>(responseStream);
                return resultResponse.tokens;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Exception getting available tokens. BaseAddress: {_hermezclient.BaseAddress} Endpoint: {endpoint} URI: {_hermezclient.BaseAddress}{endpoint}");
                throw;
            }
        }

        public async Task<string> CreateWallet(string hezEthereumAddress, string bjj, 
            string signature)
        {
            var endpoint = $"/{_apiVersion}/account-creation-authorization";
            CreateWalletRequest req = null;
            try
            {
                req = new CreateWalletRequest
                {
                    hezEthereumAddress = hezEthereumAddress,
                    bjj = bjj,
                    signature = signature
                };
                var httpResponse = await _hermezclient.PostAsync(endpoint, req);
                var responseStream = await httpResponse.Content.ReadAsStringAsync();
                if (!httpResponse.IsSuccessStatusCode) HandleErrorResponse(httpResponse, responseStream);
                var resultResponse = JsonConvert.DeserializeObject<CreateWalletResponse>(responseStream);
                return resultResponse.hezEthereumAddress;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Exception creating wallet. BaseAddress: {_hermezclient.BaseAddress} Endpoint: {endpoint} URI: {_hermezclient.BaseAddress}{endpoint}");
                _logger.LogTrace(JsonConvert.SerializeObject(req));
                throw;
            }
        }

        public async Task<AccountCreationAuthorization> GetAuth(string hezEthereumAddress)
        {
            var endpoint = $"/{_apiVersion}/account-creation-authorization/{hezEthereumAddress}";
            try
            {
                var httpResponse = await _hermezclient.GetAsync(endpoint);
                var responseStream = await httpResponse.Content.ReadAsStringAsync();
                if (!httpResponse.IsSuccessStatusCode) HandleErrorResponse(httpResponse, responseStream);
                var resultResponse = JsonConvert.DeserializeObject<AccountCreationAuthorization>(responseStream);
                return resultResponse;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Exception getting account creation authorization. BaseAddress: {_hermezclient.BaseAddress} Endpoint: {endpoint} URI: {_hermezclient.BaseAddress}{endpoint}");
                throw;
            }
        }

        public async Task<List<string>> GetAccounts()
        {
            throw new NotImplementedException();
        }
    }
}
