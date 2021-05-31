using Microsoft.Win32.SafeHandles;
using Nethereum.Signer;
using Nethereum.Signer.Crypto;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;

namespace hermezcs
{
    public class GenerateKeyResponse
    {
        public byte[] PublicKeyBytes;
        public byte[] PublicKeyNoPrefixBytes;
        public string PublicKeyAddress;
        public byte[] PrivateKeyBytes;
        public string PrivateKey;
    }

    public interface Icryptoprovider
    {
        GenerateKeyResponse GenerateKeys();
    }

    public class crypto : Icryptoprovider, IDisposable
    {
        #region Dispose

        // To detect redundant calls
        private bool _disposed = false;

        ~crypto() => Dispose(false);

        // Public implementation of Dispose pattern callable by consumers.
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // Protected implementation of Dispose pattern.
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }
            if (disposing)
            {
                // dispose managed state (managed objects).
            }
            // free unmanaged resources (unmanaged objects) and override a finalizer below.
            // set large fields to null.
            _disposed = true;
        }

        #endregion

        public GenerateKeyResponse GenerateKeys()
        {
            var k = EthECKey.GenerateKey();

            var resp = new GenerateKeyResponse();
            resp.PublicKeyBytes = k.GetPubKey();
            resp.PublicKeyNoPrefixBytes = k.GetPubKeyNoPrefix();
            resp.PublicKeyAddress = k.GetPublicAddress();
            resp.PrivateKeyBytes = k.GetPrivateKeyAsBytes();
            resp.PrivateKey = k.GetPrivateKey();

            return resp;
        }

        public string GetEncodedCompressedPublicKey(byte[] privateKey)
        {
            return EncodeCompressedPublicKey(GetCompressedPublicKey(privateKey));
        }

        public byte[] GetCompressedPublicKey(byte[] privateKey)
        {
            return new ECKey(privateKey, true).GetPubKey(true);
        }

        public string EncodeCompressedPublicKey(byte[] publicKeyCompressed)
        {
            return WebEncoders.Base64UrlEncode(publicKeyCompressed);
        }

        /// <summary>
        /// http://docs.nethereum.com/en/latest/nethereum-signing-messages/#3-hashing-and-signing-a-message-using-hashandsign
        /// </summary>
        /// <param name="message"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public string SignMessage(byte[] message, byte[] privateKey)
        {
            var signer = new EthereumMessageSigner();
            var signature = signer.HashAndSign(message, new EthECKey(privateKey, true));
            return signature;
        }
    }
}
