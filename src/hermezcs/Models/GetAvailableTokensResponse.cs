using System;
using System.Collections.Generic;

namespace hermezcs.Models
{
    public class GetAvailableTokensResponse
    {
        public int pendingItems { get; set; }
        public List<Token> tokens { get; set; }
    }
}
