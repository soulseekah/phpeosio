<?php
namespace PHPEOSIO;

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
	 * @param int $expiration When the transaction should expire. Default: 30
	 *
	 * @return array The response.
	 */
	public function push_transaction( string $account, string $action, array $data, string $authorization, int $expiration = 30 ) : array {
		if ( empty( $this->authorizations ) ) {
			throw new \Exception( 'No known authorizations. Use Client::add_key' );
		}

		if ( ! isset( $this->authorizations[ $authorization ] ) ) {
			throw new \Exception( sprintf( 'Invalid authorization for %s. Known: %s', $authorization, implode( ' ', array_keys( $this->authorizations ) ) ) );
		}

		list( $actor, $permission ) = explode( '@', $authorization );

		$ec = new \Elliptic\EC( 'secp256k1' );
		$key = $ec->keyFromPrivate( bin2hex( $this->authorizations[ $authorization ] ) );

		$info = $this->get_info();

		$transaction = $this->_serialize( [
			'expiration' => date( 'Y-m-d\TH:i:s', strtotime( $info['last_irreversible_block_time'] ) + $expiration ),
			'ref_block_num' => $info['last_irreversible_block_num'] & 0xffff,
			'ref_block_prefix' => unpack( 'V', hex2bin( mb_substr( $info['last_irreversible_block_id'], 16, 8 ) ) )[1],
			'max_net_usage_words' => 0,
			'max_cpu_usage_ms' => 0,
			'delay_sec' => 0,
			'actions' => [ [
				'account' => $account,
				'name' => $action,
				'data' => $data,
				'authorization' => [ [
					'actor' => $actor,
					'permission' => $permission,
				] ],
			] ],
			'transaction_extensions' => [],
			'context_free_actions' => [],
		], 'transaction' );

		$hash = hash( 'sha256', hex2bin( $info['chain_id'] ) . $transaction . str_repeat( "\0", 32 ) );

		$tries = 0; do {
			$signature = $key->sign( $hash, [
				'canonical' => true,
				'pers' => [ ++$tries ],
			] );

			$r = str_pad( implode( '', array_map( 'chr', $signature->r->toArray() ) ), 32, "\0", STR_PAD_LEFT );
			$s = str_pad( implode( '', array_map( 'chr', $signature->s->toArray() ) ), 32, "\0", STR_PAD_LEFT );
			$signature = mb_str_split( sprintf( '%c%s%s', max( $signature->recoveryParam + 27, $signature->recoveryParam + 31 ), $r, $s ) );
			$signature = array_map( 'ord', $signature );

			if ( ( ( ( $signature[1] & 0x80 ) === 0 ) || ( ( $signature[1] === 0 ) && ( ( $signature[2] & 0x80 ) === 0 ) ) ) && ( ( ( $signature[1] & 0x80 ) === 0 ) || ( ( $signature[1] === 0 ) && ( ( $signature[2] & 0x80 ) === 0 ) ) ) ) {
				$signature = implode( '', array_map( 'chr', $signature ) );
				break;
			}
		} while ( true );

		$base58 = new \StephenHill\Base58();
		$signature = 'SIG_K1_' . $base58->encode( $signature . mb_substr( hash( 'ripemd160', $signature . 'K1', true ), 0, 4 ) );

		return $this->_request( 'v1/chain/push_transaction', [
			'signatures' => [
				$signature,
			],
			'compression' => 'none',
			'packed_trx' => bin2hex( $transaction ),
			'packed_context_free_data' => '',
		] );
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
	 * Get table rows.
	 *
	 * @param string $account The contract that owns the table.
	 * @param string $table The table.
	 * @param string $scope The scope of the data (user).
	 * @param args $args Extra args like limit, lower_bound, etc.
	 *
	 * @return array The table rows.
	 */
	public function get_table_rows( string $account, string $table, string $scope, array $args = [] ) : array {
		$result = $this->_request( 'v1/chain/get_table_rows', array_merge( [
			'code' => $account,
			'table' => $table,
			'scope' => $scope,
		], $args ) );

		if ( empty( $result['rows'] ) ) {
			return [];
		}

		foreach ( $this->get_abi( $account )['abi']['structs'] as $struct ) {
			if ( $struct['name'] === $table ) {
				$unserialize = [ $this, '_unserialize' ];
				return array_map( function( $row ) use ( $struct, $unserialize ) {
					return $unserialize( hex2bin( $row ), 'struct', [ 'struct' => $struct ] );
				}, $result['rows'] );
			}
		}

		return [];
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
		$response = \WpOrg\Requests\Requests::post( sprintf( '%s/%s', $this->rpc_endpoint, trim( $endpoint, '/' ) ), [
			'Content-Type' => 'application/json',
		], is_null( $data ) ? '' : json_encode( $data ) )->decode_body();

		if ( isset( $response['error'] ) ) {
			throw new \Exception( sprintf( 'Invalid response from API: %s', json_encode( $response ) ) );
		}

		return $response;
	}

	/**
	 * Serialize a type.
	 *
	 * Reversed from https://github.com/EOSIO/eosjs/blob/master/src/eosjs-serialize.ts
	 *
	 * @param mixed $value The value.
	 * @param string $type The type.
	 * @param array $args Additional arguments.
	 *
	 * @return string Serialized binary data.
	 */
	private function _serialize( $value, string $type, array $args = [] ) : string {
		if ( preg_match( '#(.*?)\[\]$#', $type, $matches ) ) {
			return $this->_serialize( $value, 'array', [
				'type' => $matches[1],
				'args' => $args,
			] );
		}

		switch ( $type ):
			case 'transaction':
				$transaction_header = $this->_serialize( $value, 'struct', [
					'struct' => [
						'fields' => [
							[ 'name' => 'expiration', 'type' => 'time_point_sec' ],
							[ 'name' => 'ref_block_num', 'type' => 'uint16' ],
							[ 'name' => 'ref_block_prefix', 'type' => 'uint32' ],
							[ 'name' => 'max_net_usage_words', 'type' => 'varuint32' ],
							[ 'name' => 'max_cpu_usage_ms', 'type' => 'uint8' ],
							[ 'name' => 'delay_sec', 'type' => 'varuint32' ],
						],
					],
				] );

				$transaction = $this->_serialize( $value, 'struct', [
					'struct' => [
						'fields' => [
							[ 'name' => 'context_free_actions','type' => 'action[]' ],
							[ 'name' => 'actions', 'type' => 'action[]' ],
							[ 'name' => 'transaction_extensions', 'type' => 'pair', 'args' => [
								'type' => 'uint16',
								'data' => 'bytes',
							] ],
						],
					],
				] );

				return $transaction_header . $transaction;

			case 'action':
				$_names = [];
				foreach ( $this->get_abi( $value['account'] )['abi']['structs'] as $struct ) {
					$_names[] = $struct['name'];
					if ( $struct['name'] !== $value['name'] ) {
						continue;
					}

					return $this->_serialize( $value, 'struct', [
						'struct' => [
							'fields' => [
								[ 'name' => 'account', 'type' => 'name' ],
								[ 'name' => 'name', 'type' => 'name' ],
								[ 'name' => 'authorization', 'type' => 'struct[]', 'args' => [
									'struct' => [
										'fields' => [
											[ 'name' => 'actor', 'type' => 'name' ],
											[ 'name' => 'permission', 'type' => 'name' ],
										],
									],
								] ],
								[ 'name' => 'data', 'type' => 'struct', 'args' => [ 'bytes' => true, 'struct' => $struct, ] ]
							],
						],
					] );
				}
				throw new \Exception( sprintf( 'Action %s not found in ABI. Known: %s', $value['name'], implode( ' ', $_names ) ) );

			case 'struct':
				$serialize = [ $this, __FUNCTION__ ];
				$serialized = implode( '', array_map( function( $field ) use ( $value, $serialize ) {
					if ( ! isset( $value[ $field['name'] ] ) ) {
						throw new \Exception( sprintf( 'Missing %s %s in data', $field['type'], $field['name'] ) );
					}
					return $serialize( $value[ $field['name'] ], $field['type'], $field['args'] ?? [] );
				}, $args['struct']['fields'] ) );

				return ( $args['bytes'] ?? false ) ? $this->_serialize( $serialized, 'bytes' ) : $serialized;

			case 'name':
				if ( ! preg_match( '#^[.1-5a-z]{0,12}[.1-5a-j]?$#', $value ) ) {
					throw new \Exception( 'Name should be less than 13 characters, or less than 14 if last character is between 1-5 or a-j, and
					only contain the following symbols .12345abcdefghijklmnopqrstuvwxyz' );
				}

				$map = mb_str_split( '.12345abcdefghijklmnopqrstuvwxyz' );
				$bytes = array_map( function( $chr ) use ( $map ) {
					return str_pad( decbin( array_search( $chr, $map ) ), 5, "0", STR_PAD_LEFT );
				}, mb_str_split( $value ) );

				preg_match_all( '#[01]{8}#', str_pad( implode( '', $bytes ), 64, "0", STR_PAD_RIGHT ), $bytes );
				return str_pad( implode( '', array_map( function( $byte ) {
					return chr( bindec( $byte ) );
				}, array_reverse( $bytes[0] ) ) ), 8,"\0", STR_PAD_LEFT );

			case 'time_point_sec':
				return pack( 'V', strtotime( $value ) );

			case 'uint16':
				if ( $value != $value & 0xffff ) {
					throw new \Exception( "Value out of range for $type: $value" );
				}
				return pack( 'v', $value );

			case 'uint32':
				if ( $value != $value & 0xffffffff ) {
					throw new \Exception( "Value out of range for $type: $value" );
				}
				return pack( 'V', $value );
			case 'varuint32':
				if ( $value != $value & 0xffffffff ) {
					throw new \Exception( "Value out of range for $type: $value" );
				}
				return \Muvon\KISS\VarInt::packUint( $value );
			case 'uint8':
				if ( $value != $value & 0xff ) {
					throw new \Exception( "Value out of range for $type: $value" );
				}
				return chr( $value );

			case 'array':
				$serialize = [ $this, __FUNCTION__ ];
				return implode( '', array_merge( [ chr( count( $value ) ) ], array_map( function( $v ) use ( $serialize, $args ) {
					return $serialize( $v, $args['type'], $args['args'] ?? [] );
				}, $value ) ) );

			case 'bytes':
				return chr( mb_strlen( $value ) ) . $value;

			case 'pair':
				$length = $this->_serialize( count( $value ), 'varuint32' );

				if ( count( $value ) && count( $value ) != 2 ) {
					throw new \Exception( sprintf( 'Pair has to contain 2 values: %s', implode( ' ', array_keys( $args ) ) ) );
				}

				if ( ! $value ) {
					return $length;
				}

				return $length . $this->_serialize( $value[0], $args[0] ) . $this->_serialize( $value[1], $args[1] );

			default:
				throw new \Exception( "Unsupported serialized type $type" );
		endswitch;
	}

	/**
	 * Unserialize binary data.
	 *
	 * @param string $data The binary data.
	 * @param string $type The type.
	 * @param array $args The extra args depending on type.
	 */
	private function _unserialize( string $data, string $type, array $args = [] ) {
		$lengths = [
			'name' => 8,
			'int64' => 8, 'uint64' => 8,
		];
		switch ( $type ):
			case 'struct':
				$read = function( &$bytes, $length ) {
					$read = mb_substr( $bytes, 0, $length );
					$bytes = mb_substr( $bytes, $length );
					return $read;
				};
				$unserialize = [ $this, __FUNCTION__ ];
				return array_combine(
					array_column( $args['struct']['fields'], 'name' ),
					array_map( function( $field ) use ( $unserialize, $read, &$data, $lengths ) {
						return $unserialize( $read( $data, $lengths[ $field['type'] ] ), $field['type'] );
					}, $args['struct']['fields'] ) );
				return $result;

			case 'name':
				if ( mb_strlen( $data ) !== 8 ) {
					throw new \Exception( "name must be 64-bits in length" );
				}
				$map = array_flip( mb_str_split( '.12345abcdefghijklmnopqrstuvwxyz' ) );
				$binary = implode( '', array_reverse( array_map( function( $b ) {
					return str_pad( decbin( ord( $b ) ), 8, "0", STR_PAD_LEFT );
				}, mb_str_split( ltrim( $data, "\0" ) ) ) ) );

				preg_match_all( '#[01]{4,5}#', $binary, $bytes );
				return trim( implode( '', array_map( function( $byte ) use ( $map ) {
					return array_search( bindec( $byte ), $map );
				}, $bytes[0] ) ), '.' );

			case 'uint64':
				return 0;

			case 'int64':
				return 0;
				
			default:
				throw new \Exception( "Unsupported serialized type $type for unserialization" );
		endswitch;
	}
}
