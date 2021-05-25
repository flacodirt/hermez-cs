using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace hermezcs
{
    public static class Hex
    {
        public static int HexToInteger(byte[] hex)
        {
            var result = 0;
            for (var i = 0; i < hex.Length; i++)
                result = (result << 8) | hex[i];
            return result;
        }

        public static byte[] HexToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
                hex = "0" + hex;

            byte[] arr = new byte[hex.Length >> 1];
            for (int i = 0; i < arr.Length; ++i)
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));

            return arr;
        }

        private static int GetHexVal(char hex)
        {
            int val = hex;
            //For uppercase A-F letters:
            //return val - (val < 58 ? 48 : 55);
            //For lowercase a-f letters:
            //return val - (val < 58 ? 48 : 87);
            //Or the two combined, but a bit slower:
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        public static byte[] Join(params byte[][] values)
        {
            var len = values.Sum(i => i.Length);
            var rez = new byte[len];
            var k = 0;
            for (var i = 0; i < values.Length; i++)
            {
                var source = values[i];
                if (source.Length == 0)
                    continue;
                Array.Copy(source, 0, rez, k, source.Length);
                k += source.Length;
            }
            return rez;
        }

        public static string ToString(byte[] hex)
        {
            return string.Join(string.Empty, hex.Select(i => i.ToString("x2")));
        }
    }

    /// <summary>
    /// https://github.com/MeadowSuite/Secp256k1.Net/blob/master/Secp256k1.Net.Test/Tests.cs
    /// </summary>
    public static class Extensions
    {
        public static string ToHexString(this Span<byte> span)
        {
            return "0x" + BitConverter.ToString(span.ToArray()).Replace("-", "").ToLowerInvariant();
        }

        public static byte[] HexToBytes(this string hexString)
        {
            int chars = hexString.Length;
            byte[] bytes = new byte[chars / 2];
            for (int i = 0; i < chars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return bytes;
        }
    }

}
