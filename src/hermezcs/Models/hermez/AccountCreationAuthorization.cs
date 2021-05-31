using System;
using System.Collections.Generic;
using System.Text;

namespace hermezcs.Models.hermez
{
    public class AccountCreationAuthorization
    {
//AccountCreationAuthorization{
//timestamp*	string($date-time)
//hezEthereumAddress*	HezEthereumAddressstring
//pattern: ^hez:0x[a-fA-F0-9]{40}$
//example: hez:0xaa942cfcd25ad4d90a62358b0dd84f33b398262a

//Address of an Etherum account linked to the Hermez Network.
//bjj*	BJJstring
//pattern: ^hez:[A-Za-z0-9_-]{44}$
//example: hez:rR7LXKal-av7I56Y0dEBCVmwc9zpoLY5ERhy5w7G-xwe

//BabyJubJub compressed public key, encoded as base64 URL (RFC 4648), which result in 33 bytes. The padding byte is replaced by a sum of the encoded bytes.
//signature*	ETHSignaturestring
//pattern: ^0x[a-fA-F0-9]{130}$
//example: 0xf9161cd688394772d93aa3e7b3f8f9553ca4f94f65b7cece93ed4a239d5c0b4677dca6d1d459e3a5c271a34de735d4664a43e5a8960a9a6e027d12c562dd448e1c

//Ethereum signature.
//}

        public string timestamp { get; set; }
        public string hezEthereumAddress { get; set; }
        public string bjj { get; set; }
        public string signature { get; set; }
    }
}
