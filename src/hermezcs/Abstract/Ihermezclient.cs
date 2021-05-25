using hermezcs.Models;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace hermezcs.Abstract
{
    /// <summary>
    /// The API is the layer that allows 3rd party apps and services to interface with the coordinator
    /// to explore, monitor and use the Hermez rollup.
    /// https://docs.hermez.io/#/../developers/api?id=api
    /// https://apidoc.hermez.network/
    /// </summary>
    public interface Ihermezclient : IDisposable
    {
        Uri BaseAddress { get; }
        void SetBaseAddress(string baseAddress);
        Task<HttpResponseMessage> GetAsync(string url);
        Task<HttpResponseMessage> PostAsync(string url, object content);
    }
}
