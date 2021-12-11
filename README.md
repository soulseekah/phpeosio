# PHPEOSIO

A minimalistic and pure PHP implementation to interact with EOSIO blockchains via JSON RPC endpoints via HTTP.

## Usage

```php
// Connect to local JSON RPC endpoint via HTTP
$client = new PHPEOSIO\Client( 'http://localhost:8888' );

// Add permission with private key
$client->add_key( 'soulseekah@active', '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3' );

// Create, sign and push transaction
$client->push_transaction( 'eosio', 'bidname', [
	'bidder' => 'soulseekah',
	'newname' => 'phpeosio',
	'bid' => '1 EOS',
], 'soulseekah@active' );

// Send tokens via a transaction
$client->push_transaction( 'eosio.token', 'transfer', [
	'from': 'soulseekah',
	'to': 'eosio',
	'quantity': '10 EOS',
	'memo': 'Thank you for your service.',
], 'soulseekah@active' );
```
