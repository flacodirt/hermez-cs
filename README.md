https://gitcoin.co/issue/hermeznetwork/0xhack/3/100025693
https://github.com/hermeznetwork/hermezjs/blob/main/src/constants.js
https://docs.hermez.io/#/developers/sdk?id=configure-hermez-environment
https://docs.hermez.io/#/developers/api
https://apidoc.hermez.network/#/
https://gitcoin.co/hackathon/0x-hack/projects/5236/hermezcs
https://github.com/flacodirt/hermez-cs

# hermezCS
HermezCS is an open source SDK in dotnet core C# used to interact with the Hermez Rollup network. Hermez is a decentralised zk-rollup focused on scaling payments and token transfers on top of Ethereum. 

## SDK How-To

In these sections we will walk through the process of using the SDK to:

1. Installing HermezCS
1. Initializing HermezCS
1. Check registered tokens
1. Creating a wallet
1. Making a deposit from Ethereum into the Hermez Network
1. Verifying the balance in a Hermez account
1. Withdrawing funds back to Ethereum network
1. Making transfers
1. Verifying transaction status
1. Authorizing the creation of Hermez accounts
1. Internal accounts

### Installing HermezCS

### Initializing HermezCS

1. Create Transaction Pool

Initialize the storage where user transactions are stored. This needs to be initialized at the start of your application.

JS:
hermez.TxPool.initializeTransactionPool()

### Check registered tokens

Before being able to operate on the Hermez Network, we must ensure that the token we want to operate with is listed. For that we make a call to the Hermez Coordinator API that will list all available tokens. All tokens in Hermez Network must be ERC20.

We can see there are 2 tokens registered. ETH will always be configured at index 0. The second token is HEZ. For the rest of the examples we will work with ETH. In the future, more tokens will be included in Hermez.

JS:
const token = await hermez.CoordinatorAPI.getTokens()
const tokenERC20 = token.tokens[0]
console.log(token)

https://apidoc.hermez.network/#/Explorer/getTokens
curl -X GET "https://api.testnet.hermez.io/v1/tokens?order=ASC" -H  "accept: application/json"

