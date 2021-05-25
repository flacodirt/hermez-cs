using Microsoft.AspNetCore.WebUtilities;
using Nethereum.Signer.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace hermezcs
{
    public class Addresses
    {
        /// <summary>
        /// Get the hermez address representation of an ethereum address
        /// </summary>
        /// <param name="ethereumAddress"></param>
        /// <returns></returns>
        public string GetHermezAddress(string ethereumAddress)
        {
            return $"{Constants.HERMEZ_PREFIX}{ethereumAddress}";
        }

        /// <summary>
        /// Gets the Ethereum address part of a Hermez address
        /// </summary>
        /// <param name="hezEthereumAddress"></param>
        /// <returns></returns>
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
        /// Get API Bjj compressed data format
        /// </summary>
        /// <param name="bjjCompressedHex"></param>
        /// <returns></returns>
        public string HexToBase64BJJ(byte[] privateKey)//string bjjCompressedHex)
        {
            //see: https://github.com/hermeznetwork/hermezjs/blob/main/src/addresses.js
            //do we need to swap endian?
            //do we need to calc/append sum byte?
            var compressedPublicKey = new ECKey(privateKey, true).GetPubKey(true);
            var encodedB64CompressedPublicKey = WebEncoders.Base64UrlEncode(compressedPublicKey);
            return $"{Constants.HERMEZ_PREFIX}{encodedB64CompressedPublicKey}";
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
