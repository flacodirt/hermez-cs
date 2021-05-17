using hermezcs.Models;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace hermezcs.Abstract
{
    public interface Ihermezclient : IDisposable
    {
        Uri BaseAddress { get; }
        void SetBaseAddress(string baseAddress);
        Task<HttpResponseMessage> GetAsync(string url);
        Task<HttpResponseMessage> PostAsync(string url, object content);
    }
}
