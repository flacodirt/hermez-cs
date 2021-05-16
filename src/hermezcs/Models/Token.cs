using System;

namespace hermezcs.Models
{
    public class Token
    {
        public int itemId { get; set; }
        public int id { get; set; }
        public int ethereumBlockNum { get; set; }
        public string ethereumAddress { get; set; }
        public string name { get; set; }
        public string symbol { get; set; }
        public int decimals { get; set; }
        public double USD { get; set; }
        public DateTime fiatUpdate { get; set; }
    }
}
