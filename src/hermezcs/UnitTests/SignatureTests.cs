using hermezcs.Abstract;
using hermezcs.Models;
using Microsoft.Extensions.Logging;
using Nethereum.Signer;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace hermezcs.UnitTests
{
    public class SignatureTests : BaseTest
    {
        [Fact]
        public void Signature_ShouldVerify()
        {
            // construct request
            var addresses = new Addresses();
            var bjjPubComp = addresses.HexToBase64BJJ(BJJ_DEV_PRIVATE_KEY);
            var req = new CreateWalletRequest
            {
                hezEthereumAddress = $"{HERMEZ_PREFIX}{ETH_DEV_PUBLIC_ADDRESS}",
                bjj = bjjPubComp
            };
            Assert.Matches(hezEthereumAddressPattern, req.hezEthereumAddress);
            Assert.Matches(bjjAddressPattern, req.bjj);
            var messageContentString = JsonConvert.SerializeObject(req, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });

            // sign msg with ETH PRVT KEY
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(messageContentString, new EthECKey(ETH_DEV_PRIVATE_KEY_STR));
            //"0x8a133b60c41afba8d200a72f68d61f1447faa3d6b053efa88983c865678dd0c8725087d4ba6df7a2b3f4c391b27d6de3db52ef432c412f06f018c171efdf65c11b"

            // Recover signer ETH PUB address from a message by using their signature
            var recoveredPubAddy = signer.EncodeUTF8AndEcRecover(messageContentString, signature); // "0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C"
            Assert.Equal(ETH_DEV_PUBLIC_ADDRESS, recoveredPubAddy);
        }

        [Fact]
        public void SignatureB_ShouldVerify()
        {
            // construct request
            var addresses = new Addresses();
            var bjjPubComp = addresses.HexToBase64BJJ(BJJ_DEV_PRIVATE_KEY);
            var req = new CreateWalletRequest
            {
                hezEthereumAddress = $"{HERMEZ_PREFIX}{ETH_DEV_PUBLIC_ADDRESS}",
                bjj = bjjPubComp
            };
            Assert.Matches(hezEthereumAddressPattern, req.hezEthereumAddress);
            Assert.Matches(bjjAddressPattern, req.bjj);
            
            var messageContentString = JsonConvert.SerializeObject(req, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });

            // sign msg with ETH PRVT KEY
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(messageContentString, new EthECKey(ETH_DEV_PRIVATE_KEY_STR));
            //"0x8a133b60c41afba8d200a72f68d61f1447faa3d6b053efa88983c865678dd0c8725087d4ba6df7a2b3f4c391b27d6de3db52ef432c412f06f018c171efdf65c11b"

            // whats actually put on wire
            req.signature = signature;
            var actualMsgString = JsonConvert.SerializeObject(req, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });

            //^-- if you try to Recover signature from full serialized message WITH signature in object, it will FAIL...
            // have to REMOVE the signature from the received object to match serialized object that was signed...

            //deserialize
            var receiveDes = JsonConvert.DeserializeObject<CreateWalletRequest>(actualMsgString);
            var receivedSig = receiveDes.signature;
            receiveDes.signature = null;
            var verifyMe = JsonConvert.SerializeObject(receiveDes, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });

            // Recover signer ETH PUB address from a message by using their signature
            var recoveredPubAddy = signer.EncodeUTF8AndEcRecover(verifyMe, receivedSig); // "0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C"
            Assert.Equal(ETH_DEV_PUBLIC_ADDRESS, recoveredPubAddy);
        }


        [Fact]
        public void Signature_Testing_ShouldVerify()
        {
            // construct request
            var addresses = new Addresses();
            var bjjPubComp = addresses.HexToBase64BJJ(BJJ_DEV_PRIVATE_KEY);
            var req = new CreateWalletRequest
            {
                hezEthereumAddress = $"{HERMEZ_PREFIX}{ETH_DEV_PUBLIC_ADDRESS}",
                bjj = bjjPubComp
            };
            Assert.Matches(hezEthereumAddressPattern, req.hezEthereumAddress);
            Assert.Matches(bjjAddressPattern, req.bjj);
            var messageContentString = JsonConvert.SerializeObject(req, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });

            using (var sha256 = SHA256.Create())
            {
                var hashA = Hex.HexToBytes(messageContentString);
                var hashB = Encoding.UTF8.GetBytes(messageContentString);
                var hashC = Encoding.Unicode.GetBytes(messageContentString);
                var hash = sha256.ComputeHash(hashA);

                // sign msg with ETH KEY
                var signer = new EthereumMessageSigner();

                var signature1 = signer.EncodeUTF8AndSign(messageContentString, new EthECKey(ETH_DEV_PRIVATE_KEY_STR));
                //"0x8a133b60c41afba8d200a72f68d61f1447faa3d6b053efa88983c865678dd0c8725087d4ba6df7a2b3f4c391b27d6de3db52ef432c412f06f018c171efdf65c11b"

                //var signature2 = signer.HashAndSign(messageContentString, ETH_DEV_PRIVATE_KEY_STR);
                //"0x6169ef08c33f588fdbcd3e258cfd3db9cba401118b45766c51e1ef6aa244611003aa63904b24287c2a9b38853dc4a388eb421c2a239e770978219eb0161dcce91c"

                //var signature3 = signer.Sign(Encoding.UTF8.GetBytes(messageContentString), ETH_DEV_PRIVATE_KEY_STR);
                //"0x8a133b60c41afba8d200a72f68d61f1447faa3d6b053efa88983c865678dd0c8725087d4ba6df7a2b3f4c391b27d6de3db52ef432c412f06f018c171efdf65c11b"

                //var signature4 = signer.Sign(Encoding.Unicode.GetBytes(messageContentString), ETH_DEV_PRIVATE_KEY_STR);
                //"0xd9b1bf482aa48298b5e099dd6387c2cd6b5c53e83e1ae283e911ca7429653a4b534a3f614f25badb8ae197cb8126ae8c5b7fce50b7952f980c21c95ae7c83ba21c"

                //var a = new Nethereum.Signer.Crypto.ECKey(Hex.HexToBytes(ETH_DEV_PRIVATE_KEY_STR), true);
                //var ecdsaSig = a.Sign(hash);
                //var derA = ecdsaSig.ToDER();
                //var isGoodA = a.Verify(hash, ecdsaSig);

                //var b = new EthECKey(ETH_DEV_PRIVATE_KEY_STR);
                //var ethEcdsaSig = b.Sign(hash);
                //var b64array = ethEcdsaSig.To64ByteArray();
                //var derB = ethEcdsaSig.ToDER();
                //var isGoodB = b.Verify(hash, ethEcdsaSig);

                // Recover signer address from a message by using their signature
                //var ve1 = signer.EcRecover(bytesToHash, signature1); // "0xd3c3A71Ad78305651E0A57e9AeD27bD11e632b3E"
                //var ve2 = signer.EcRecover(hash, signature1); // "0x30D76FbdcD7df9c426Fb3DC340D98AC3033D36da"
                var ve3 = signer.EncodeUTF8AndEcRecover(messageContentString, signature1); // "0x0CDB2c68b5f2c2Fb31128FD4bC32d8e0503fAb5C"
                Assert.Equal(ETH_DEV_PUBLIC_ADDRESS, ve3);
                //var ve4 = signer.HashAndEcRecover(messageContentString, signature1); // "0x54966965F9Bb461382DF1e1F9D67443684427302"
            }
        }


    }
}
