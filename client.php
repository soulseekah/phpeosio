<?php
namespace PHPEOSIO;

require __DIR__ . '/vendor/autoload.php';

mb_internal_encoding( '8bit' );

class Client {
	/**
	 * @var Stores authorizations and their keys.
	 */
	private array $authorizations = [];

	/**
	 * @var The RPC endpoint URL (HTTP).
	 */
	private string $rpc_endpoint = '';

	/**
	 * Constructor.
	 *
	 * @param string $rpc_endpoint The RPC endpoint to connect to.
	 */
	public function __construct( string $rpc_endpoint ) {
		$this->rpc_endpoint = ltrim( $rpc_endpoint, '/' );
	}

	/**
	 * Add permission and private key to keychain.
	 *
	 * Throws exception on invalid private key.
	 *
	 * @see https://developers.eos.io/manuals/eos/latest/keosd/wallet-specification/
	 *
	 * @param string $authorization An authorization in the `actor@permission` format. Example: `soulseekah@owner`
	 * @param string $key The private key. Example: `5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU`
	 */
	public function add_key( string $authorization, string $key ) {
		$base58 = new \StephenHill\Base58();
		$decoded = $base58->decode( $key );

		list( $version, $key, $checksum ) = [
			mb_substr( $decoded, 0, 1 ),
			mb_substr( $decoded, 1, 32 ),
			mb_substr( $decoded, 33, 4 ),
		];

		if ( $version != chr( 0x80 ) ) {
			throw new \Exception( sprintf( 'Expected key version 0x80. Got: 0x%02x', ord( $version ) ) );
		}

		$verify = mb_substr( hash( 'sha256', hash( 'sha256', "$version$key", true ), true ), 0, 4 );

		if ( $verify !== $checksum ) {
			throw new \Exception( sprintf( 'Invalid checksum: 0x%s. Expected: 0x%s', bin2hex( $verify ), bin2hex( $checksum ) ) );
		}

		if ( ! preg_match( '#^\w+@\w+$#', $authorization ) ) {
			throw new \Exception( 'Authorization must be in actor@permission format.' );
		}

		$this->authorizations[ $authorization ] = $key;
	}

	/**
	 * Assemble, sign and push a transaction with a single action.
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
		if ( empty( $this->authorizations ) ) {
			throw new \Exception( 'No known authorizations. Use Client::add_key' );
		}

		if ( ! isset( $this->authorizations[ $authorization ] ) ) {
			throw new \Exception( sprintf( 'Invalid authorization for %s. Known: %s', $authorization, implode( ' ', array_keys( $this->authorizations ) ) ) );
		}

		list( $actor, $permission ) = explode( '@', $authorization );

		$ec = new \Elliptic\EC( 'secp256k1' );
		$base58 = new \StephenHill\Base58();

		$key = $ec->keyFromPrivate( bin2hex( $this->authorizations[ $authorization ] ) );
		$public = hex2bin( $key->getPublic( true, 'hex' ) );
		$checksum = mb_substr( hash( 'ripemd160', $public, true ), 0, 4 );
		$public = 'EOS' . $base58->encode( "$public$checksum" );

		var_dump( $this->get_info() );
		exit;

		$transaction = [
			'actions' => [ [
				'account' => $account,
				'name' => $action,
				'data' => $data,
				'authorization' => [ [
					'actor' => $actor,
					'permission' => $permission,
				] ],
			] ],
			'context_free_data' => [],
		];
	}

	/**
	 * Get ABI.
	 *
	 * @param string $account The account to get the ABI for.
	 *
	 * @return array The ABI.
	 */
	public function get_abi( string $account ) : array {
		return $this->_request( 'v1/chain/get_abi', [ 'account_name' => $account ] );
	}

	/**
	 * Get blockchain info.
	 *
	 * @return array The blockchain info.
	 */
	public function get_info() : array {
		return $this->_request( 'v1/chain/get_info' );
	}

	/**
	 * Make HTTP request.
	 *
	 * @param string $endpoint The endpoint.
	 * @param array $data The data.
	 *
	 * @return array The response.
	 */
	private function _request( string $endpoint, array $data = null ) : array {
		$response = \Requests::post( sprintf( '%s/%s', $this->rpc_endpoint, trim( $endpoint, '/' ) ), [
			'Content-Type' => 'application/json',
		], is_null( $data ) ? '' : json_encode( $data ) )->decode_body();

		if ( isset( $response['error'] ) ) {
			throw new \Exception( sprintf( 'Invalid response from API: %s', json_encode( $response ) ) );
		}

		return $response;
	}
}
