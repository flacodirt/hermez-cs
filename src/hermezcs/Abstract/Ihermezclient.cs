using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace hermezcs.Abstract
{
    public interface Ihermezclient : IDisposable
    {
        void SetBaseAddress(string baseAddress);
        Task<HttpResponseMessage> GetAsync(string url);
        Uri BaseAddress { get; }
    }
}
