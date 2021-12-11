<?php
namespace PHPEOSIO;

class Client {
	/**
	 * @var $permission Stores authorizations and their keys.
	 */
	private array $authorizations = [];

	/**
	 * Constructor.
	 *
	 * @param string $rpc_endpoint The RPC endpoint to connect to.
	 */
	public function __construct( string $rpc_endpoint ) {
	}

	/**
	 * Add permission and private key to keychain.
	 *
	 * @param string $authorization An authorization in the `actor@permission` format. Example: `soulseekah@owner`
	 * @param string $key The private key. Example: `5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3`
	 */
	public function add_key( string $authorization, string $key ) {
	}

	/**
	 * Push a transaction with a single action.
	 *
	 * Will throw exceptions in case of failures.
	 *
	 * @param string $account The account (contract). Example: `eosio`
	 * @param string $action The action. `bidname`
	 * @param array $data The data as a JSON-serializable array. Example: `{"bidder":"soulseekah","newname":"phpeosio","bid":"1.0000 EOS"}`
	 * @param string $authorization The authorization name. Example `soulseekah@active`
	 *
	 * @return string The transaction ID.
	 */
	public function push_transaction( string $account, string $action, array $data, string $authorization ) : string {
	}
}
