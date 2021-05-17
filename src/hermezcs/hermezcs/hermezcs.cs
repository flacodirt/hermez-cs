using hermezcs.Abstract;
using hermezcs.Models;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
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

        public async Task<List<Token>> GetAvailableTokens()
        {
            var endpoint = $"/{_apiVersion}/tokens";
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
                _logger.LogError(ex, $"Exception getting available tokens. BaseAddress: {_hermezclient.BaseAddress} Endpoint: {endpoint} URI: {_hermezclient.BaseAddress}{endpoint}");
                throw;
            }
        }

        public async Task<string> CreateWallet(string hezEthereumAddress, string bjj, string signature)
        {
            var endpoint = $"/{_apiVersion}/account-creation-authorization";
            CreateWalletRequest req = null;
            try
            {
                req = new CreateWalletRequest
                {
                    hezEthereumAddress = hezEthereumAddress,
                    bjj = bjj
                };

                //GenerateSignature(req, endpoint);

                var httpResponse = await _hermezclient.PostAsync(endpoint, req);
                httpResponse.EnsureSuccessStatusCode();
                var responseStream = await httpResponse.Content.ReadAsStringAsync();
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

        public void GenerateSignature(CreateWalletRequest req, string endpoint)
        {
            var serializedBody = new JsonContent(req);
            var requestUri = new Uri(_hermezclient.BaseAddress + endpoint);

            // Compute a content hash.
            var contentHash = ComputeContentHash(serializedBody.ToString());
            //Specify the Coordinated Universal Time (UTC) timestamp.
            var date = DateTimeOffset.UtcNow.ToString("r", CultureInfo.InvariantCulture);
            //Prepare a string to sign.
            var stringToSign = $"POST\n{requestUri.PathAndQuery}\n{date};{requestUri.Authority};{contentHash}";
            //Compute the signature.
            req.signature = ComputeSignature(stringToSign);
        }

        static string ComputeContentHash(string content)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
                return Convert.ToBase64String(hashedBytes);
            }
        }

        static string ComputeSignature(string stringToSign)
        {
            string secret = "resourceAccessKey";
            using (var hmacsha256 = new HMACSHA256(Convert.FromBase64String(secret)))
            {
                var bytes = Encoding.ASCII.GetBytes(stringToSign);
                var hashedBytes = hmacsha256.ComputeHash(bytes);
                return Convert.ToBase64String(hashedBytes);
            }
        }

        public async Task<List<string>> GetAccounts()
        {
            throw new NotImplementedException();
        }
    }
}
