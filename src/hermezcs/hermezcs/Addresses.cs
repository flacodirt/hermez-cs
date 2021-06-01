using Microsoft.AspNetCore.WebUtilities;
using Nethereum.Signer.Crypto;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace hermezcs
{
    public class Addresses
    {
        /// <summary>
        /// Get the hermez address representation of an ethereum address
        /// </summary>
        /// <param name="ethereumAddress"></param>
        /// <returns>hezEthereumAddress</returns>
        public string GetHermezAddress(string ethereumAddress)
        {
            return $"{Constants.HERMEZ_PREFIX}{ethereumAddress}";
        }

        /// <summary>
        /// Gets the Ethereum address part of a Hermez address
        /// </summary>
        /// <param name="hezEthereumAddress"></param>
        /// <returns>ethereumAddress</returns>
        public string GetEthereumAddress(string hezEthereumAddress)
        {
            if (hezEthereumAddress.Contains($"{Constants.HERMEZ_PREFIX}"))
            {
                return hezEthereumAddress.Replace($"{Constants.HERMEZ_PREFIX}", "");
            }
            else
            {
                return hezEthereumAddress;
            }
        }

        /// <summary>
        /// Checks if given string matches regex of a Ethereum address
        /// </summary>
        /// <param name="ethereumAddress"></param>
        /// <returns></returns>
        public bool IsEthereumAddress(string ethereumAddress)
        {
            return Constants.EthereumAddressPattern.IsMatch(ethereumAddress);
        }

        /// <summary>
        /// Checks if given string matches regex of a Hermez address
        /// </summary>
        /// <param name="hermezEthereumAddress"></param>
        /// <returns></returns>
        public bool IsHermezEthereumAddress(string hermezEthereumAddress)
        {
            return Constants.HezEthereumAddressPattern.IsMatch(hermezEthereumAddress);
        }

        /// <summary>
        /// Checks if given string matches regex of a Hermez BJJ address
        /// </summary>
        /// <param name="bjjAddress"></param>
        /// <returns></returns>
        public bool IsHermezBjjAddress(string bjjAddress)
        {
            return Constants.BjjAddressPattern.IsMatch(bjjAddress);
        }

        /// <summary>
        /// Extracts the account index from the address with the hez prefix
        /// </summary>
        /// <param name="hezAccountIndex"></param>
        /// <returns></returns>
        public int GetAccountIndex(string hezAccountIndex)
        {
            var colonIndex = hezAccountIndex.LastIndexOf(':') + 1;
            return Int32.Parse(hezAccountIndex.Substring(colonIndex));
        }

        /// <summary>
        /// Checks if given string matches regex of a Hermez account index
        /// </summary>
        /// <param name="test"></param>
        /// <returns></returns>
        public bool IsHermezAccountIndex(string test)
        {
            return Constants.AccountIndexPattern.IsMatch(test);
        }

        /// <summary>
        /// Equiv of function hexToBase64BJJ
        /// From: https://github.com/hermeznetwork/hermezjs/blob/db9a45831937da3de39dc8888423692c2f875436/src/addresses.js#L88
        /// 
        /// Get API Bjj compressed data format
        /// @param {String} bjjCompressedHex - Bjj compressed address encoded as hex string
        /// @returns {String} API adapted bjj compressed address
        ///
        /// </summary>
        /// <param name="bjjCompressedHex"></param>
        /// <returns></returns>
        /// <returns>API adapted bjj compressed address</returns>
        public string HexToBase64BJJ(string bjjCompressedHex)
        {
            var hexToBytesA = Hex.HexToBytes(bjjCompressedHex); // handles with or without prefix
            //var hexToBytesB = bjjCompressedHex.HexToBytes(); // has to have prefix
            //var hexToBytesC = Encoding.UTF8.GetBytes(bjjCompressedHex); // too many bytes

            var bjjSwapBuffer = hexToBytesA;
            //var bjjSwapBuffer = hexToBytesB;

            bjjSwapBuffer = SumBytes(bjjSwapBuffer);
            //byte[] finalBuffBjj = bjjSwapBuffer.Concat(sumBuff).ToArray();

            var encodedB64CompressedPublicKey = WebEncoders.Base64UrlEncode(bjjSwapBuffer);
            var finalReturn = $"hez:{encodedB64CompressedPublicKey}";
            return finalReturn;
        }

        public string HexToBase64BJJ(byte[] privateKey)
        { throw new NotImplementedException(); }


        public byte[] SumBytes(byte[] pubKeyCompressed)
        {
            int sum = 0;
            for (var i = 0; i < pubKeyCompressed.Length; i++)
            {
                sum += pubKeyCompressed[i];

                //JS: sum = sum % 2 ** 8
                //sum ^= pubKeyCompressed[i];       // "checksum verification failed"
                sum = (int)Math.Pow((sum % 2), 8);  // "invalid signature"
            }

            var sumByte = Convert.ToByte(sum);
            pubKeyCompressed[pubKeyCompressed.Length - 1] = sumByte;
            return pubKeyCompressed;
        }

        /// <summary>
        /// Gets the Babyjubjub hexadecimal from its base64 representation
        /// </summary>
        /// <param name="base64BJJ"></param>
        /// <returns></returns>
        public byte[] Base64ToHexBJJ(string base64BJJ)
        {
            if (base64BJJ.Contains($"{Constants.HERMEZ_PREFIX}"))
            {
                base64BJJ = base64BJJ.Replace($"{Constants.HERMEZ_PREFIX}", "");
            }
            return WebEncoders.Base64UrlDecode(base64BJJ);
        }
    }
}
