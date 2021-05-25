using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace hermezcs
{
    public static class Constants
    {
        public static string HERMEZ_PREFIX = "hez:";
        public static Regex EthereumAddressPattern = new Regex("^0x[a-fA-F0-9]{40}$");
        public static Regex HezEthereumAddressPattern = new Regex("^hez:0x[a-fA-F0-9]{40}$");
        public static Regex BjjAddressPattern = new Regex("^hez:[A-Za-z0-9_-]{44}$");
        public static Regex AccountIndexPattern = new Regex("^hez:[a-zA-Z0-9]{2,6}:[0-9]{0,9}$");


    }
}
