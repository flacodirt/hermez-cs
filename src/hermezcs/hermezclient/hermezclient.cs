using hermezcs.Abstract;
using hermezcs.Models;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace hermezcs.hermezclient
{
	public class hermezclient : Ihermezclient
	{
		private readonly HttpClient _httpClient;
		public Uri BaseAddress { get { return _httpClient.BaseAddress; } }
		
		public hermezclient(string baseAddress = "")
		{
			_httpClient = new HttpClient();
			if (!string.IsNullOrEmpty(baseAddress))
				SetBaseAddress(baseAddress);
        }
		public void SetBaseAddress(string baseAddress)
		{
			_httpClient.BaseAddress = new Uri(baseAddress);
		}

		public async Task<HttpResponseMessage> GetAsync(string url)
		{
			return await _httpClient.GetAsync(url);
		}

		public async Task<HttpResponseMessage> PostAsync(string url, object content)
		{
			return await _httpClient.PostAsync(url, new JsonContent(content));
		}

		public void Dispose()
		{
			_httpClient?.Dispose();
		}

    }
}
