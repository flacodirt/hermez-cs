# hermezCS

Hermez is a decentralised zk-rollup focused on scaling payments and token transfers on top of Ethereum. 

HermezCS is a dotnet core C# SDK which allows a dotnet core C# application to integrate with the Hermez Network API.

The Hermez Network API is the layer that allows 3rd party apps and services to interface with the coordinator to explore, monitor and use the layer two features of the Hermez rollup.

Example of these apps include:

    Wallet: send L2 transactions, check balance, ...
    Explorer: List transactions, slots, batches, ...
    Exchange integrations

## Developers Guide

HermezCS is developed entirely using dotnet core C# v3.1 LTS and is comprised of several projects described below:

- Abstract: Interface definitions for the SDK itself and the Client used to communicate with the Hermez API.
- hermezclient: Implementation of the Client interface used to communicate with the Hermez API. This implementation is using HttpClient.
- hermezcs: Implementation of the SDK interface used to integrate with the Hermez Network. This implementation is dotnet core C# netstandard2.0.
- IntegrationTests: Integration Test project used to fully test components reaching out to the Hermez Test Network.
- Models: Model definitions including all response objects from the Hermez Network.
- UnitTests: Unit Test project used to test the inner business logic of the SDK to ensure the SDK works as expected given expected mocked results from the Hermez Network.

## SDK How-To

In these sections we will walk through the process of using the SDK to:

1. Installing HermezCS
1. Importing HermezCS
1. Initializing HermezCS
1. Checking if token exists in Hermez Network
1. Creating a wallet
1. Depositing Tokens from Ethereum into Hermez Network
1. Verifying the balance in a Hermez account
1. Withdrawing funds Hermez Network back to Ethereum network
1. Making transfers
1. Verifying transaction status
1. Authorizing the creation of Hermez accounts
1. Creating internal accounts

### Installing HermezCS

The following `dotnet` commands will build and compile the binaries from the source files.

```
dotnet restore
dotnet build -c Release --no-restore
dotnet test --no-restore
dotnet publish -c Release -o out --no-restore
```

### Importing HermezCS

Add the compiled .DLL file to your project references.

Add the using statement in your project file.

```
using hermezcs;
```

### Initializing HermezCS

#### Create Transaction Pool

@TODO: Not needed with CS?

#### Configure Hermez Environment

### Checking if token exists in Hermez Network

Before being able to operate on the Hermez Network, we must ensure that the token we want to operate with is listed. For that we make a call to the Hermez Coordinator API that will list all available tokens. All tokens in Hermez Network must be ERC20.

We can see there are 2 tokens registered. ETH will always be configured at index 0. The second token is HEZ. For the rest of the examples we will work with ETH. In the future, more tokens will be included in Hermez.

```
//act
var tokens = await sdk.GetAvailableTokens();

//assert
Assert.True(tokens.Count > 1);
Assert.Equal("ETH", tokens[0].symbol);
```

**Below is a work-in-progress**

### Creating a Wallet

We can create a new Hermez wallet by providing the Ethereum private key of an Ethereum account. This wallet will store the Ethereum and Baby JubJub keys for the Hermez account. The Ethereum address is used to authorize L1 transactions, and the Baby JubJub key is used to authorize L2 transactions. We will create two wallets.

### Depositing Tokens from Ethereum into Hermez Network

Creating a Hermez account and depositing tokens is done simultaneously as an L1 transaction. In this example we are going to deposit 1 ETH tokens into the newly created Hermez accounts. 

### Verifying the balance in a Hermez account

A token balance can be obtained by querying the API and passing the hermezEthereumAddress of the Hermez account.

### Withdrawing funds Hermez Network back to Ethereum network

Withdrawing funds is a two step process:

    Exit
    Withdrawal

#### Exit

#### Withdrawal

#### Force Exit

### Making transfers

### Verifying transaction status

### Authorizing the creation of Hermez accounts

### Creating internal accounts

# Getting Started

1. User connects wallet to Hermez Network. This will automatically drive a Hermez account from the Ethereum account. This will then lead to an empty wallet.
1. The next step is to make a deposit. 

Deposit:

1. Select token
1. Select amount
1. Deposit

Transfer:

1. Select token
1. Select recepient
1. Select amount
1. Transfer

Confirmation:

Deposit - L1 - sign with Ethereum wallet

## Accounts

Making Deposits creates accounts.

## Transactions

Opening an account shows all the transactions related to that account.

Opening a transaction shows information related to that transaction.

## Withdrawals

Withdrawals are a two-part process. After completing the first part explained above, a card appears on the Home screen or on the respective account page. When ready, it will show a button to finalize the withdrawal.

*Withdrawals require paying a gas fee on L1, insufficient gas in your L1 account will cause the withdrawal to stall.

*Withdrawals are final and cannot be stopped, reversed, or altered in any way after initiated. 

# Considerations

- hermezclient: HttpClient automatic retry logic

- Docker

# Notes

https://gitcoin.co/issue/hermeznetwork/0xhack/3/100025693

https://github.com/hermeznetwork/hermezjs/blob/main/src/constants.js

https://docs.hermez.io/#/developers/sdk?id=configure-hermez-environment

https://docs.hermez.io/#/developers/api

https://apidoc.hermez.network/#/

https://gitcoin.co/hackathon/0x-hack/projects/5236/hermezcs

https://github.com/flacodirt/hermezcs
