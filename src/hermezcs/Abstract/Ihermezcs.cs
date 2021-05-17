using hermezcs.Models;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace hermezcs.Abstract
{
    public interface Ihermezcs
    {
        /// <summary>
        /// Before being able to operate on the Hermez Network, we must ensure that the token we want to operate with is listed.
        /// For that we make a call to the Hermez Coordinator API that will list all available tokens.
        /// All tokens in Hermez Network must be ERC20.
        /// https://docs.hermez.io/#/developers/sdk?id=check-token-exists-in-hermez-network
        /// </summary>
        /// <returns></returns>
        Task<List<Token>> GetAvailableTokens();
        /// <summary>
        /// We can create a new Hermez wallet by providing the Ethereum private key of an Ethereum account.
        /// This wallet will store the Ethereum and Baby JubJub keys for the Hermez account.
        /// The Ethereum address is used to authorize L1 transactions.
        /// The Baby JubJub key is used to authorize L2 transactions.
        /// </summary>
        /// <returns></returns>
        Task<string> CreateWallet(string hezEthereumAddress, string bjj, string signature);
        Task<List<string>> GetAccounts();
    }
}
