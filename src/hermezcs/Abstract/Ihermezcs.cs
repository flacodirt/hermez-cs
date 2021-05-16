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
        Task<List<string>> GetAccounts();
    }
}
