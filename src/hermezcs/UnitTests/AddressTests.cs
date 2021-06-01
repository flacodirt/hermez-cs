using Microsoft.AspNetCore.WebUtilities;
using Nethereum.Signer.Crypto;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace hermezcs.UnitTests
{
    public class AddressTests : BaseTest
    {
        [Fact]
        public void GetHermezAddress_WithEthAddy_ShouldReturnHezPrefixAddy()
        {
            var addresses = new Addresses();
            var hezPrefixAddy = addresses.GetHermezAddress(ETH_DEV_PUBLIC_ADDRESS);
            Assert.Matches(hezEthereumAddressPattern, hezPrefixAddy);
        }

        [Fact]
        public void GetEthereumAddress_WithHezAddy_ShouldReturnEthAddy()
        {
            var addresses = new Addresses();
            var ethAddy = addresses.GetEthereumAddress(hermezEthereumAddress);
            Assert.Matches(ethereumAddressPattern, ethAddy);
        }

        [Fact]
        public void isEthereumAddress_WithEthAddy_ShouldReturnTrue()
        {
            var addresses = new Addresses();
            var res = addresses.IsEthereumAddress(ETH_DEV_PUBLIC_ADDRESS);
            Assert.True(res);
        }

        [Fact]
        public void isEthereumAddress_WithHezAddy_ShouldReturnFalse()
        {
            var addresses = new Addresses();
            var res = addresses.IsEthereumAddress(hermezEthereumAddress);
            Assert.False(res);
        }

        [Fact]
        public void isHermezEthereumAddress_WithHezAddy_ShouldReturnTrue()
        {
            var addresses = new Addresses();
            var res = addresses.IsHermezEthereumAddress(hermezEthereumAddress);
            Assert.True(res);
        }

        [Fact]
        public void isHermezEthereumAddress_WithEthAddy_ShouldReturnFalse()
        {
            var addresses = new Addresses();
            var res = addresses.IsHermezEthereumAddress(ETH_DEV_PUBLIC_ADDRESS);
            Assert.False(res);
        }

        [Fact]
        public void isHermezBjjAddress_WithBjjAddy_ShouldReturnTrue()
        {
            var addresses = new Addresses();
            var bjj = addresses.HexToBase64BJJ(BJJ_DEV_PRIVATE_KEY);
            var res = addresses.IsHermezBjjAddress(bjj);
            Assert.True(res);
        }

        [Fact]
        public void isHermezBjjAddress_WithEthAddy_ShouldReturnFalse()
        {
            var addresses = new Addresses();
            var res = addresses.IsHermezBjjAddress(ETH_DEV_PUBLIC_ADDRESS);
            Assert.False(res);
        }

        [Fact]
        public void isHermezBjjAddress_WithHezAddy_ShouldReturnFalse()
        {
            var addresses = new Addresses();
            var res = addresses.IsHermezBjjAddress(hermezEthereumAddress);
            Assert.False(res);
        }

        [Fact]
        public void HexToBase64BJJ_WithPrivateKey_ShouldReturnString()
        {
            var addresses = new Addresses();
            var res = addresses.HexToBase64BJJ(BJJ_DEV_PRIVATE_KEY);

            var compressedPublicKey = new ECKey(BJJ_DEV_PRIVATE_KEY, true).GetPubKey(true);
            var encodedB64CompressedPublicKey = WebEncoders.Base64UrlEncode(compressedPublicKey);
            Assert.Equal($"{Constants.HERMEZ_PREFIX}{encodedB64CompressedPublicKey}", res);
        }

        [Fact]
        public void base64ToHexBJJ_WithB64String_ShouldReturnHexBJJ()
        {
            var addresses = new Addresses();

            // this takes private key bytes
            // makes compressed public key bytes
            // makes b64urlencoded string of compressed public key
            // returns prefix+b64 string
            var b64e = addresses.HexToBase64BJJ(BJJ_DEV_PRIVATE_KEY.ToHexString());

            // this takes prefix+b64 string
            // removes prefix
            // decode b64urlencoded string of compressed public key to bytes
            // returns compressed public key bytes
            var res = addresses.Base64ToHexBJJ(b64e);

            // gets compressed public key
            // compare to private bytes made to compress public key
            var compressedPublicKey = new ECKey(BJJ_DEV_PRIVATE_KEY, true).GetPubKey(true);

            Assert.Equal(compressedPublicKey, res);
        }
    }
}
