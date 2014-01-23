<?php

/**
 *
 * nanoserv - a sockets daemon toolkit for PHP 5.1+
 * 
 * Copyright (C) 2004-2013 Vincent Negrier aka. sIX <six at aegis-corp.org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 *
 * @package nanoserv
 * @subpackage Core
 */

namespace Nanoserv;

/**
 * nanoserv current version number
 * @var string
 */
const VERSION = "2.1.2-dev";

/**
 * Base exception class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 2.0
 */
abstract class Exception extends \Exception {

	public $addr;

	public function __construct($errmsg, $errno, $addr) {

		parent::__construct($errmsg, $errno);

		$this->addr = $addr;

	}

}

/**
 * Server exception class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 2.0
 */
class Server_Exception extends Exception {

	public $listener;

	public function __construct($errmsg, $errno, $addr, Listener $listener = NULL) {

		parent::__construct($errmsg, $errno, $addr);

		$this->listener = $listener;
	
	}

}

/**
 * Client exception class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 2.0
 */
class Client_Exception extends Exception {

	public $handler;

	public function __construct($errmsg, $errno, $addr, Handler $handler = NULL) {

		parent::__construct($errmsg, $errno, $addr);

		$this->handler = $handler;
	
	}

}

/**
 * Base socket class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
class Socket {

	/**
	 * Maximum number of bytes read by Read()
	 * @var int
	 */
	const DEFAULT_READ_LENGTH = 16384;
	
	/**
	 * Internal Socket unique ID
	 * @var int
	 */
	public $id;
	
	/**
	 * Socket stream descriptor
	 * @var resource
	 */
	public $fd;

	/**
	 * Is the socket connected ?
	 * @var bool
	 */
	public $connected = false;
	
	/**
	 * Is the socket waiting to be connected ?
	 * @var bool
	 */
	public $pending_connect = false;
	
	/**
	 * Is the socket waiting for ssl/tls handshake ?
	 * @var bool
	 */
	public $pending_crypto = false;
	
	/**
	 * Is the socket blocked ?
	 * @var bool
	 */
	public $blocked = false;
	
	/**
	 * Should we block reading from this socket ?
	 * @var bool
	 */
	public $block_reads = false;
	
	/**
	 * Stream context
	 * @var resource
	 */
	protected $context;
	
	/**
	 * Crypto type
	 * @var int
	 */
	public $crypto_type;
	
	/**
	 * Attached handler
	 * @var Connection_Handler
	 */
	public $handler;
	
	/**
	 * Static instance counter
	 * @var int
	 */
	private static $sck_cnt;
	
	/**
	 * Socket contructor
	 *
	 * @param resource $fd
	 */
	public function __construct($fd = false, $crypto_type = false) {

		if ($fd === false) {
		
			$this->context = stream_context_create();

		} else {

			$this->fd = $fd;
			$this->connected = true;
			$this->Set_Blocking(false);
			$this->Set_Timeout(0);

			if ($crypto_type) $this->crypto_type = $crypto_type;
		
		}
	
		$this->id = ++Socket::$sck_cnt;
	
	}
	
	/**
	 * Get stream options
	 *
	 * @return array
	 * @since 0.9
	 */
	public function Get_Options() {

		if ($this->fd) {

			return stream_context_get_options($this->fd);

		} else {

			return stream_context_get_options($this->context);

		}

	}
	
	/**
	 * Set a stream context option
	 *
	 * @param string $wrapper
	 * @param string $opt
	 * @param mixed $val
	 * @return bool
	 * @since 0.9
	 */
	public function Set_Option($wrapper, $opt, $val) {

		if ($this->fd) {

			return stream_context_set_option($this->fd, $wrapper, $opt, $val);

		} else {

			return stream_context_set_option($this->context, $wrapper, $opt, $val);

		}
	
	}
	
	/**
	 * Set timeout
	 * 
	 * @param int $timeout
	 * @return bool
	 * @since 0.9
	 */
	protected function Set_Timeout($timeout) {

		return stream_set_timeout($this->fd, $timeout);
	
	}
	
	/**
	 * Sets wether the socket is blocking or not
	 *
	 * @param bool $block
	 * @return bool
	 * @since 0.9
	 */
	protected function Set_Blocking($block) {

		return stream_set_blocking($this->fd, $block);

	}

	/**
	 * Flag the socket so that the main loop won't read from it even if data is available.
	 *
	 * This can be used to implement flow control when proxying data between two asymetric connections for example.
	 *
	 * @param bool $block
	 * @return bool the previous status
	 * @since 2.0.3
	 */
	public function Block_Reads($block) {

		$ret = $this->block_reads;

		$this->block_reads = $block;

		return $ret;
	
	}
	
	
	/**
	 * Set the stream write buffer (PHP defaults to 8192 bytes)
	 *
	 * @param int $buffer_size
	 * @return int
	 * @since 2.0
	 */
	public function Set_Write_Buffer($buffer_size) {

		return stream_set_write_buffer($this->fd, $buffer_size);
	
	}
	
	/**
	 * Enable or disable ssl/tls crypto on the socket
	 *
	 * @param bool $enable
	 * @param int $type 
	 * @return mixed
	 * @since 0.9
	 */
	public function Enable_Crypto($enable = true, $type = false) {

		if ($type) $this->crypto_type = $type;
		
		$ret = @stream_socket_enable_crypto($this->fd, $enable, $this->crypto_type);
		
		$this->pending_crypto = $ret === 0;

		return $ret;
		
	}
	
	/**
	 * Setup crypto if needed
	 *
	 * @return bool
	 * @since 0.9
	 */
	public function Setup() {

		if (isset($this->crypto_type)) return $this->Enable_Crypto();

		return true;
		
	}
	
	/**
	 * Get local socket name
	 *
	 * @return string
	 * @since 0.9
	 */
	public function Get_Name() {

		return stream_socket_get_name($this->fd, false);

	}
	
	/**
	 * Get remote socket name
	 *
	 * @return string
	 * @since 0.9
	 */
	public function Get_Peer_Name() {

		return stream_socket_get_name($this->fd, true);

	}
	
	/**
	 * Read data from the socket and return it
	 *
	 * @param int $length maximum read length
	 * @return string
	 * @since 0.9
	 */
	public function Read() {

		return fread($this->fd, self::DEFAULT_READ_LENGTH);

	}

	/**
	 * Read data from a non connected socket and return it
	 *
	 * @param string &$addr contains the message sender address upon return
	 * @param int $len maximum read length
	 * @return string
	 * @since 0.9.61
	 */
	public function Read_From(&$addr, $len = 16384) {

		return stream_socket_recvfrom($this->fd, $len, NULL, $addr);

	}
	
	/**
	 * Write data to the socket
	 *
	 * write returns the number of bytes written to the socket
	 *
	 * @param string $data
	 * @return int
	 * @since 0.9
	 */
	public function Write($data) {

		$nb = fwrite($this->fd, $data);

		if (isset($data[$nb])) $this->blocked = true;

		return $nb;
	
	}
	
	/**
	 * Write data to a non connected socket
	 *
	 * @param string $to in the form of "<ip_address>:<port>"
	 * @param string $data
	 * @return int
	 * @since 0.9.61
	 */
	public function Write_To($to, $data) {

		return stream_socket_sendto($this->fd, $data, NULL, $to);
	
	}
	
	/**
	 * Write data from stream to socket
	 *
	 * returns the number of bytes read from the stream and written to the socket
	 *
	 * @param resource $stream
	 * @param int $len maximum length (bytes) to read/write
	 * @return int
	 * @since 2.1
	 */
	public function Write_From_Stream($stream, $len = 16384) {
		
		return stream_copy_to_stream($stream, $this->fd, $len);
	
	}
	
	/**
	 * Query end of stream status
	 *
	 * @return bool
	 * @since 0.9
	 */
	public function Eof() {

		$fd = $this->fd;
		
		if (!is_resource($fd)) return true;

		stream_socket_recvfrom($fd, 1, STREAM_PEEK);
		
		return feof($fd);

	}
	
	/**
	 * Close the socket
	 * @since 0.9
	 */
	public function Close() {

		@fclose($this->fd);

		$this->connected = $this->pending_connect = false;

	}

	/**
	 * Socket destructor
	 */
	public function __destruct() {

		Core::Free_Write_Buffers($this->id);

		$this->Close();

	}

}

/**
 * Server socket class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
class Server_Socket extends Socket {

	/**
	 * Listen address (format is 'proto://addr:port')
	 * @var string
	 */
	public $address;

	/**
	 * Real listen address (format is 'proto://addr:port')
	 * @var string
	 */
	private $real_address;

	/**
	 * Server_Socket constructor
	 */
	public function __construct($addr) {

		parent::__construct();
		
		$this->address = $addr;

		$proto = strtolower(strtok($addr, ":"));

		if (($proto === "udp") || ($proto === "unix")) {

			$this->real_address = $addr;
		
		} else {
		
			$this->real_address = "tcp:" . strtok("");

			if ($proto !== "tcp") switch ($proto) {

				case "ssl":		$this->crypto_type = STREAM_CRYPTO_METHOD_SSLv23_SERVER;	break;
				case "tls":		$this->crypto_type = STREAM_CRYPTO_METHOD_TLS_SERVER;		break;
				case "sslv2":	$this->crypto_type = STREAM_CRYPTO_METHOD_SSLv2_SERVER;		break;
				case "sslv3":	$this->crypto_type = STREAM_CRYPTO_METHOD_SSLv3_SERVER;		break;

				default:		
					
				if (defined($cname = "STREAM_CRYPTO_METHOD_".strtoupper($proto)."_SERVER")) {
					
					$this->crypto_type = constant($cname);

				} else {

					throw new Server_Exception("unknown transport/crypto type '{$proto}'");
				
				}
			
			}

		}
	
	}

	/**
	 * Start listening and accepting connetions
	 *
	 * @return bool
	 * @since 0.9
	 */
	public function Listen($bind_only = false) {

		$errno = $errstr = false;
		
		$this->fd = @stream_socket_server($this->real_address, $errno, $errstr, STREAM_SERVER_BIND | ($bind_only ? 0 : STREAM_SERVER_LISTEN), $this->context);

		if ($this->fd === false) {

			throw new Server_Exception("cannot listen to {$this->real_address}: {$errstr}", $errno, $this->real_address);
		
		}

		$this->Set_Blocking(false);
		$this->Set_Timeout(0);
		
		return true;

	}

	/**
	 * Accept connection
	 *
	 * @return resource
	 * @since 0.9
	 */
	public function Accept() {

		return @stream_socket_accept($this->fd, 0);

	}

}


/**
 * Client socket class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
class Client_Socket extends Socket {

	/**
	 * Connect timeout (seconds)
	 * @var int
	 */
	const CONNECT_TIMEOUT = 10;
	
	/**
	 * Peer address (format is 'proto://addr:port')
	 * @var string
	 */
	public $address;

	/**
	 * Connect timeout (timestamp)
	 * @var int
	 */
	public $connect_timeout;
	
	/**
	 * Client_Socket constructor
	 */
	public function __construct($addr) {

		parent::__construct();
		
		$this->address = $addr;

		$proto = strtolower(strtok($addr, ":"));
		$s = strtok("");

		if (($proto === "udp") || ($proto === "unix")) {

			$this->real_address = $addr;
		
		} else {
		
			$this->real_address = "tcp:" . $s;

			if ($proto != "tcp") switch ($proto) {

				case "ssl":		$this->crypto_type = STREAM_CRYPTO_METHOD_SSLv23_CLIENT;	break;
				case "tls":		$this->crypto_type = STREAM_CRYPTO_METHOD_TLS_CLIENT;		break;
				case "sslv2":	$this->crypto_type = STREAM_CRYPTO_METHOD_SSLv2_CLIENT;		break;
				case "sslv3":	$this->crypto_type = STREAM_CRYPTO_METHOD_SSLv3_CLIENT;		break;

				default:		if (defined($cname = "STREAM_CRYPTO_METHOD_".strtoupper($proto)."_CLIENT")) $this->crypto_type = constant($cname);
			
			}

		}
	
	}

	/**
	 * Connect to the peer address
	 *
	 * @param int $timeout connection timeout in seconds
	 * @return bool
	 * @since 0.9
	 */
	public function Connect($timeout = false) {

		$errno = $errstr = false;

		$this->fd = @stream_socket_client($this->real_address, $errno, $errstr, 3, STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT, $this->context);

		if ($this->fd === false) {

			throw new Client_Exception("cannot connect to {$this->real_address}: {$errstr}", $errno, $this->real_address);
		
		}

		if ($timeout === false) $timeout = self::CONNECT_TIMEOUT;
		
		$this->connect_timeout = microtime(true) + $timeout;
		$this->pending_connect = true;
		$this->connected = false;
		$this->Set_Blocking(false);
		$this->Set_Timeout(0);
		
		return true;

	}

}


/**
 * IPC Socket class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
class IPC_Socket extends Socket {

	/**
	 * Maximum size of inter process communication packets
	 * @var int
	 */
	const IPC_MAX_PACKET_SIZE = 1048576;

	/**
	 * pid number of the remote forked process
	 * @var int
	 */
	public $pid;
	
	/**
	 * IPC Socket constructor
	 *
	 * @param resource $fd
	 * @param int $pid
	 */
	public function __construct($fd, $pid=false) {

		parent::__construct($fd);

		$this->Set_Write_Buffer(self::IPC_MAX_PACKET_SIZE);
		$this->pid = $pid;

	}

	/**
	 * Read data from IPC socket
	 *
	 * @return string
	 * @since 0.9
	 */
	public function Read() {

		return fread($this->fd, self::IPC_MAX_PACKET_SIZE);

	}

	/**
	 * Creates a pair of connected, indistinguishable pipes
	 *
	 * Returns an array of two IPC_Socket objects
	 *
	 * @param int $domain
	 * @param int $type
	 * @param int $proto
	 * @return array
	 * @since 0.9
	 */
	static public function Pair($domain = STREAM_PF_UNIX, $type = STREAM_SOCK_DGRAM, $proto = 0) {

		list($s1, $s2) = stream_socket_pair($domain, $type, $proto);

		return array(new IPC_Socket($s1), new IPC_Socket($s2));

	}
	
	/**
	 * Ask the master process for object data
	 *
	 * @param array $request
	 * @param bool $need_response
	 * @return mixed
	 * @since 0.9
	 */
	public function Ask_Master($request, $need_response = true) {

		$this->Write(serialize($request));

		if (!$need_response) return;
		
		$rfd = array($this->fd);
		$dfd = array();
		
		if (@stream_select($rfd, $dfd, $dfd, 600)) return unserialize($this->Read());

	}

}

/**
 * Timer class
 *
 * Do not instanciate Timer but use the Core::New_Timer() method instead
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
class Timer {

	/**
	 * System time for timer activation
	 * @var float
	 */
	public $microtime;

	/**
	 * Timer callback
	 * @var mixed
	 */
	public $callback;

	/**
	 * Timer status
	 * @var bool
	 */
	public $active = true;
	
	/**
	 * Timer constructor
	 *
	 * @param float $time
	 * @param mixed $callback
	 * @since 0.9
	 * @see Core::New_Timer()
	 */
	public function __construct($time, $callback) {

		$this->microtime = $time;
		$this->callback = $callback;
	
	}

	/**
	 * Activate timer
	 *
	 * Timers are activated by default, and Activate should only be used after a call do Deactivate()
	 *
	 * @see Timer::Deactivate()
	 */
	public function Activate() {

		$this->active = true;

	}

	/**
	 * Deactivate timer
	 */
	public function Deactivate() {

		$this->active = false;

	}

}

/**
 * Write buffer interface
 */
interface I_Write_Buffer {

	/**
	 * Setup a new write buffer
	 *
	 * @param Socket $socket
	 * @param mixed $data
	 * @param mixed $callback
	 */
	public function __construct(Socket $socket, $data, $callback = false);

	/**
	 * Get availability of data
	 *
	 * @return bool
	 * @since 0.9
	 */
	public function Waiting_Data();

	/**
	 * Write data to socket and advance buffer pointer
	 *
	 * @param int $length
	 */
	public function Write($length = NULL);

}

/**
 * Write buffer base class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
abstract class Write_Buffer {

	/**
	 * Attached socket
	 * @var Socket
	 */
	public $socket;
	
	/**
	 * Buffered data
	 * @var string
	 */
	protected $data;

	/**
	 * End-of-write Callback
	 * @var mixed
	 */
	protected $callback = false;

	/**
	 * Write_Buffer constructor
	 *
	 * @param Socket $socket
	 * @param mixed $data
	 * @param mixed $callback
	 */
	public function __construct(Socket $socket, $data, $callback = false) {

		$this->socket = $socket;
		$this->data = $data;
		$this->callback = $callback;
	
	}
	
	/**
	 * Write_Buffer destructor
	 */
	public function __destruct() {

		if ($this->callback) call_user_func($this->callback, $this->Waiting_Data());
	
	}

}


/**
 * Static write buffer class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
class Static_Write_Buffer extends Write_Buffer implements I_Write_Buffer {

	/**
	 * Buffered data pointer
	 * @var int
	 */
	private $pointer = 0;
	
	/**
	 * Get availability of data
	 *
	 * @return bool
	 * @since 0.9
	 */
	public function Waiting_Data() {

		return isset($this->data[$this->pointer]);
		
	}

	/**
	 * Write data to socket and advance buffer pointer
	 *
	 * @param int $length
	 * @since 1.1
	 */
	public function Write($length = 16384) {

		$this->pointer += $this->socket->Write(substr($this->data, $this->pointer, $length));
	
	}
	
}


/**
 * Stream write buffer class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 2.1
 */
class Stream_Write_Buffer extends Write_Buffer implements I_Write_Buffer {

	/**
	 * Get availability of data from stream
	 *
	 * @return bool
	 * @since 0.9
	 */
	public function Waiting_Data() {

		return !@feof($this->data);
		
	}

	/**
	 * Read data from stream and write it to socket
	 *
	 * @param int $length
	 * @since 1.1
	 */
	public function Write($length = 16384) {

		return $this->socket->Write_From_Stream($this->data, $length);
	
	}

}

/**
 * Base handler class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
abstract class Handler {

	/**
	 * Attached socket
	 * @var Socket
	 */
	public $socket;

	/**
	 * Set a stream context option
	 *
	 * @param string $wrapper
	 * @param string $opt
	 * @param mixed $val
	 * @return bool
	 * @since 0.9
	 */
	public function Set_Option($wrapper, $opt, $val) {

		return $this->socket->Set_Option($wrapper, $opt, $val);
	
	}

}


/**
 * Datagram listener / handler class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9.61
 */
abstract class Datagram_Handler extends Handler {

	/**
	 * Is the listener active ?
	 * @var bool
	 */
	public $active = false;

	/**
	 * Datagram_Handler constructor
	 *
	 * @param string $addr
	 * @param string $handler_classname
	 * @param mixed $handler_options
	 */
	public function __construct($addr) {

		$this->socket = new Server_Socket($addr);
	
	}
	
	/**
	 * Activate the listener
	 *
	 * @return bool
	 * @since 0.9.61
	 */
	public function Activate() {

		try {
		
			if ($ret = $this->socket->Listen(true)) $this->active = true;
			
			return $ret;
	
		} catch (Server_Exception $e) {

			throw new Server_Exception($e->getMessage(), $e->getCode(), $e->addr, $this);
		
		}
	
	}

	/**
	 * Deactivate the listener
	 * @since 0.9.61
	 */
	public function Deactivate($close_socket = true) {

		if ($close_socket) {
			
			$this->socket->Close();

		}

		$this->active = false;
	
	}

	/**
	 * Send data over the connection
	 *
	 * @param string $to in the form of "<ip_address>:<port>"
	 * @param string $data
	 * @return int
	 * @since 0.9.61
	 */
	public function Write($to, $data) {

		return $this->socket->Write_To($to, $data);
	
	}

	/**
	 * Event called on data reception
	 *
	 * @param string $from
	 * @param string $data
	 * @since 0.9.61
	 */
	public function on_Read($from, $data) {

	}
	
	/**
	 * Datagram_Handler destructor
	 */
	public function __destruct() {

		$this->Deactivate();

	}
	
}


/**
 * Connection handler class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
abstract class Connection_Handler extends Handler {

	/**#@+
	 * Cause of connection failure
	 * @var int
	 */
	const FAIL_CONNREFUSED = 1;
	const FAIL_TIMEOUT = 2;
	const FAIL_CRYPTO = 3;
	/**#@-*/
	
	/**
	 * Send data over the connection
	 *
	 * @param string $data
	 * @param mixed $callback
	 * @return Static_Write_Buffer
	 * @since 0.9
	 */
	public function Write($data, $callback=false) {

		return Core::New_Static_Write_Buffer($this->socket, $data, $callback);

	}

	/**
	 * Send open stream over the connection
	 *
	 * @param resource $stream
	 * @param mixed $callback
	 * @return Stream_Write_Buffer
	 * @since 2.1
	 */
	public function Write_Stream($stream, $callback=false) {

		return Core::New_Stream_Write_Buffer($this->socket, $stream, $callback);

	}
	
	/**
	 * Connect
	 *
	 * @param int $timeout timeout in seconds
	 * @since 0.9
	 */
	public function Connect($timeout=false) {

		try {
		
			$this->socket->Connect($timeout);

		} catch (Client_Exception $e) {

			Core::Free_Connection($this);
			
			throw new Client_Exception($e->getMessage(), $e->getCode(), $e->addr, $this);
		
		}
	
	}

	/**
	 * Disconnect
	 */
	public function Disconnect() {

		$this->socket->Close();

		Core::Free_Connection($this);

	}
	
	/**
	 * Event called on received connection
	 * @since 0.9
	 */
	public function on_Accept() {

	}

	/**
	 * Event called on established connection
	 * @since 0.9
	 */
	public function on_Connect() {
		
	}

	/**
	 * Event called on failed connection
	 *
	 * @param int $failcode see Connection_Handler::FAIL_* constants
	 * @since 0.9
	 */
	public function on_Connect_Fail($failcode) {
		
	}
	
	/**
	 * Event called on disconnection
	 * @since 0.9
	 */
	public function on_Disconnect() {

	}

	/**
	 * Event called on data reception
	 *
	 * @param string $data
	 * @since 0.9
	 */
	public function on_Read($data) {

	}

	/**
	 * Event called before forking
	 *
	 * @since 2.0
	 */
	public function on_Fork_Prepare() {

	}

	/**
	 * Event called after forking, both on master and child processes
	 *
	 * @since 2.0
	 */
	public function on_Fork_Done() {

	}

}


/**
 * Listener class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
class Listener {

	/**
	 * Attached socket
	 * @var Server_Socket
	 */
	public $socket;

	/**
	 * Name of the handler class
	 * @var string
	 * @see NS_Connetion_Handler
	 */
	public $handler_classname;

	/**
	 * Handler options
	 *
	 * this is passed as the first constructor parameter of each spawned connection handlers
	 *
	 * @var mixed
	 */
	public $handler_options;

	/**
	 * Is the listener active ?
	 * @var bool
	 */
	public $active = false;
	
	/**
	 * If set the listener will fork() a new process for each accepted connection
	 * @var bool
	 */
	public $forking = false;
	
	/**
	 * Listener constructor
	 *
	 * @param string $addr
	 * @param string $handler_classname
	 * @param mixed $handler_options
	 */
	public function __construct($addr, $handler_classname, $handler_options=false, $forking=false) {

		$this->socket = new Server_Socket($addr);
		$this->handler_classname = $handler_classname;
		$this->handler_options = $handler_options;
		$this->forking = ($forking && is_callable("pcntl_fork"));
	
	}

	/**
	 * Set a stream context option
	 *
	 * @param string $wrapper
	 * @param string $opt
	 * @param mixed $val
	 * @return bool
	 * @since 0.9
	 */
	public function Set_Option($wrapper, $opt, $val) {

		return $this->socket->Set_Option($wrapper, $opt, $val);
	
	}
	
	/**
	 * Sets wether the listener should fork() a new process for each accepted connection
	 *
	 * @param bool $forking
	 * @return bool
	 * @since 0.9
	 */
	public function Set_Forking($forking=true) {

		if ($forking && !is_callable("pcntl_fork")) return false;
		
		$this->forking = $forking;

		return true;
	
	}
	
	/**
	 * Activate the listener
	 *
	 * @return bool
	 * @since 0.9
	 */
	public function Activate() {

		try {
		
			if ($ret = $this->socket->Listen()) $this->active = true;
			
			return $ret;
	
		} catch (Server_Exception $e) {

			throw new Server_Exception($e->getMessage(), $e->getCode(), $e->addr, $this);

		}
	
	}

	/**
	 * Deactivate the listener
	 * @since 0.9
	 */
	public function Deactivate() {

		$this->socket->Close();
		$this->active = false;
	
	}

	/**
	 * Listener destructor
	 */
	public function __destruct() {

		$this->Deactivate();

	}

}


/**
 * Shared object class for inter-process communications
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
class Shared_Object {

	/**
	 * caller process pid
	 * @var int
	 */
	static public $caller_pid;
	
	/**
	 * shared object unique identifier
	 * @var int
	 */
	public $_oid;
	
	/**
	 * wrapped object
	 * @var object
	 */
	private $wrapped;

	/**
	 * static instance counter
	 * @var int
	 */
	static public $shared_count = 0;
	
	/**
	 * Shared_Object constructor
	 *
	 * If $o is omited, a new StdClass object will be created and wrapped
	 *
	 * @param object $o
	 */
	public function __construct($o=false) {

		if ($o === false) $o = new StdClass();

		$this->_oid = ++self::$shared_count;
		$this->wrapped = $o;
	
	}
	
	public function __get($k) {

		if (Core::$child_process) {

			return Core::$master_pipe->Ask_Master(array("oid" => $this->_oid, "action" => "G", "var" => $k));
			
		} else {
		
			return $this->wrapped->$k;

		}

	}

	public function __set($k, $v) {

		if (Core::$child_process) {

			Core::$master_pipe->Ask_Master(array("oid" => $this->_oid, "action" => "S", "var" => $k, "val" => $v), false);
		
		} else {
		
			$this->wrapped->$k = $v;

		}
	
	}

	public function __call($m, $a) {

		if (Core::$child_process) {

			return Core::$master_pipe->Ask_Master(array("oid" => $this->_oid, "action" => "C", "func" => $m, "args" => $a));

		} else {
		
			return call_user_func_array(array($this->wrapped, $m), $a);

		}
	
	}

}


/**
 * Server / multiplexer class
 *
 * @package nanoserv
 * @subpackage Core
 * @since 0.9
 */
final class Core {

	/**
	 * nanoserv current version number
	 * @var string
	 */
	const VERSION = "2.1.2-dev";
	
	/**
	 * Registered listeners
	 * @var array
	 */
	static private $listeners = array();

	/**
	 * Write buffers
	 * @var array
	 */
	static private $write_buffers = array();
	
	/**
	 * Active connections
	 * @var array
	 */
	static private $connections = array();
	
	/**
	 * Active datagram handlers
	 * @var array
	 */
	static private $dgram_handlers = array();
	
	/**
	 * Shared objects
	 * @var array
	 */
	static private $shared_objects = array();

	/**
	 * Forked process pipes
	 * @var array
	 */
	static private $forked_pipes = array();
	
	/**
	 * Timers
	 * @var array
	 */
	static private $timers = array();
	
	/**
	 * Timers updated
	 * @var bool
	 */
	static private $timers_updated = false;
	
	/**
	 * Number of active connection handler processes
	 * @var int
	 */
	static public $nb_forked_processes = 0;
	
	/**
	 * Maximum number of active children before incoming connections get delayed
	 * @var int
	 */
	static public $max_forked_processes = 64;
	
	/**
	 * Are we master or child process ?
	 * @var bool
	 */
	static public $child_process = false;
	
	/**
	 * Forked server handled connection
	 * @var Connection_Handler
	 */
	static private $forked_connection;
	
	/**
	 * Forked server pipe to the master process
	 * @var Socket
	 */
	static public $master_pipe;
	
	/**
	 * Class Nanoserv should not be instanciated but used statically
	 */
	private function __construct() {

	}
	
	/**
	 * Register a new listener
	 *
	 * For consistency New_Listener() will also wrap Core::New_Datagram_Handler() if the given addr is of type "udp"
	 *
	 * @param string $addr
	 * @param string $handler_classname
	 * @param mixed $handler_options
	 * @return Listener
	 * @see Listener
	 * @see Datagram_Handler
	 * @since 0.9
	 */
	static public function New_Listener($addr, $handler_classname, $handler_options=false) {

		if (strtolower(strtok($addr, ":")) == "udp") {

			$l = self::New_Datagram_Handler($addr, $handler_classname);
		
		} else {
		
			$l = new Listener($addr, $handler_classname, $handler_options);
			self::$listeners[] = $l;

		}
		
		return $l;

	}

	/**
	 * Deactivate and free a previously registered listener
	 *
	 * For consistency Free_Listener() will also wrap Core::Free_Datagram_Handler() if the given object is an instance of Datagram_Handler
	 *
	 * @param Listener $l
	 * @return bool
	 * @see Listener
	 * @see Datagram_Handler
	 * @since 0.9
	 */
	static public function Free_Listener($l) {

		if ($l instanceof Listener) {
		
			foreach (self::$listeners as $k => $v) if ($v === $l) {

				unset(self::$listeners[$k]);
				return true;
			
			}

		} else if ($l instanceof Datagram_Handler) {

			return self::Free_Datagram_Handler($l);
		
		}
		
		return false;
	
	}

	/**
	 * Register a new static write buffer
	 *
	 * This method is used by Connection_Handler::Write() and should not be 
	 * called unless you really know what you are doing
	 *
	 * @param Socket $socket
	 * @param string $data
	 * @param mixed $callback
	 * @return Static_Write_Buffer
	 * @see Connection_Handler::Write()
	 * @since 0.9
	 */
	static public function New_Static_Write_Buffer(Socket $socket, $data, $callback=false) {

		$wb = new Static_Write_Buffer($socket, $data, $callback);

		$wb->Write();

		if ($wb->Waiting_Data()) {
		
			self::$write_buffers[$socket->id][] = $wb;

		}

		return $wb;
	
	}

	/**
	 * Register a new static write buffer
	 *
	 * This method is used by Connection_Handler::Write_Stream() and should not be 
	 * called unless you really know what you are doing
	 *
	 * @param Socket $socket
	 * @param resource $stream
	 * @param mixed $callback
	 * @return Stream_Write_Buffer
	 * @see Connection_Handler::Write_Stream()
	 * @since 0.9
	 */
	static public function New_Stream_Write_Buffer(Socket $socket, $data, $callback=false) {

		$wb = new Stream_Write_Buffer($socket, $data, $callback);

		$wb->Write();

		if ($wb->Waiting_Data()) {
		
			self::$write_buffers[$socket->id][] = $wb;

		}

		return $wb;
	
	}
	
	/**
	 * Free a registered write buffer
	 *
	 * @param int $sid socket id
	 * @since 0.9
	 */
	static public function Free_Write_Buffers($sid) {

		unset(self::$write_buffers[$sid]);
	
	}
	
	/**
	 * Register a new outgoing connection
	 * 
	 * @param string $addr
	 * @param string $handler_classname
	 * @param mixed $handler_options
	 * @return Connection_Handler
	 * @see Connection_Handler
	 * @since 0.9
	 */
	static public function New_Connection($addr, $handler_classname, $handler_options=false) {

		$sck = new Client_Socket($addr);
		$h = new $handler_classname($handler_options);

		$h->socket = $sck;

		self::$connections[$sck->id] = $h;
		
		return $h;
	
	}
	
	/**
	 * Free an allocated connection
	 *
	 * @param Connection_Handler $h
	 * @return bool
	 * @since 0.9
	 */
	static public function Free_Connection(Connection_Handler $h) {

		$so = $h->socket;
		
		unset(self::$connections[$so->id]);
		self::Free_Write_Buffers($so->id);

		$so->pending_connect = $so->pending_crypto = $so->connected = false;

		if (self::$child_process && (self::$forked_connection === $h)) exit();

		return true;
	
	}

	/**
	 * Register a new datagram (udp) handler
	 *
	 * @param string $addr
	 * @param string $handler_classname
	 * @return Datagram_Handler
	 * @see Datagram_Handler
	 * @since 0.9.61
	 */
	static public function New_Datagram_Handler($addr, $handler_classname) {

		$h = new $handler_classname($addr);
		self::$dgram_handlers[$h->socket->id] = $h;

		return $h;
	
	}
	
	/**
	 * Deactivate and free a datagram handler
	 *
	 * @param Datagram_Handler $h
	 * @return bool
	 * @since 0.9.61
	 */
	static public function Free_Datagram_Handler(Datagram_Handler $h) {

		unset(self::$dgram_handlers[$h->socket->id]);

		return true;

	}
	
	/**
	 * Register a new shared object
	 *
	 * shared objects allow forked processes to use objects stored on the master process
	 * if $o is ommited, a new StdClass empty object is created
	 *
	 * @param object $o
	 * @return Shared_Object
	 * @since 0.9
	 */
	static public function New_Shared_Object($o = false) {

		$shr = new Shared_Object($o);

		self::$shared_objects[$shr->_oid] = $shr;

		return $shr;
	
	}
	
	/**
	 * Free a shared object
	 *
	 * @param Shared_Object $o
	 * @since 0.9
	 */
	static public function Free_Shared_Object(Shared_Object $o) {

		unset(self::$shared_objects[$o->_oid]);
	
	}
	
	/**
	 * Register a new timer callback
	 *
	 * @param float $delay specified in seconds
	 * @param mixed $callback may be "function" or array($obj, "method")
	 * @return Timer
	 * @since 0.9
	 */
	static public function New_Timer($delay, $callback) {

		$t = new Timer(microtime(true) + $delay, $callback);
		
		self::$timers[] = $t;
		self::$timers_updated = true;

		return $t;
	
	}
	
	/**
	 * Clear all existing timers
	 *
	 * @return int number of timers cleared
	 * @since 2.0
	 */
	static public function Clear_Timers() {

		$ret = count(self::$timers);
		
		self::$timers = array();

		return $ret;
	
	}
	
	/**
	 * Get all registered Connection_Handler objects
	 *
	 * Note: connections created by fork()ing listeners can not be retreived this way
	 *
	 * @param bool $include_pending_connect
	 * @return array
	 * @since 0.9
	 */
	static public function Get_Connections($include_pending_connect=false) {

		$ret = array();
		
		foreach (self::$connections as $c) if ($c->socket->connected || $include_pending_connect) $ret[] = $c;

		return $ret;
	
	}
	
	/**
	 * Get all registered Listener objects
	 *
	 * @param bool $include_inactive
	 * @return array
	 * @since 0.9
	 */
	static public function Get_Listeners($include_inactive=false) {

		$ret = array();
		
		foreach (self::$listeners as $l) if ($l->active || $include_inactive) $ret[] = $l;

		return $ret;
	
	}
	
	/**
	 * Get all registered Timer objects
	 *
	 * @param bool $include_inactive
	 * @return array
	 * @since 2.0.1
	 */
	static public function Get_Timers($include_inactive=false) {

		$ret = array();

		foreach (self::$timers as $t) if ($t->active || $include_inactive) $ret[] = $t;

		return $ret;

	}
	
	/**
	 * Set the maximum number of allowed children processes before delaying incoming connections
	 *
	 * Note: this setting only affect and applies to forking listeners
	 *
	 * @param int $i
	 * @since 2.0
	 */
	static public function Set_Max_Children($i) {

		self::$max_forked_processes = $i;

	}
	
	/**
	 * Flush all write buffers
	 *
	 * @since 2.0
	 */
	static public function Flush_Write_Buffers() {

		while (self::$write_buffers) {

			self::Run(1);

		}
	
	}
	
	/**
	 * Fork and setup IPC sockets
	 *
	 * @return int the pid of the created process, 0 if child process
	 * @since 0.9.63
	 */
	static public function Fork() {

		if ($has_shared = (Shared_Object::$shared_count > 0)) {

			list($s1, $s2) = IPC_Socket::Pair();
		
		}
		
		$pid = pcntl_fork();

		if ($pid === 0) {

			self::$child_process = true;

			if ($has_shared) {
			
				self::$master_pipe = $s2;

			}
			
		} else if ($pid > 0) {

			++self::$nb_forked_processes;

			if ($has_shared) { 

				$s1->pid = $pid;
				self::$forked_pipes[$pid] = $s1;
			
			}
		
		}

		return $pid;
	
	}
	
	/**
	 * Enter main loop
	 *
	 * The <var>$time</var> parameter can have different meanings:
	 * <ul>
	 * <li>int or float > 0 : the main loop will run once and will wait for activity for a maximum of <var>$time</var> seconds</li>
	 * <li>0 : the main loop will run once and will not wait for activity when polling, only handling waiting packets and timers</li>
	 * <li>int or float < 0 : the main loop will run for -<var>$time</var> seconds exactly, whatever may happen</li>
	 * <li>NULL : the main loop will run forever</li>
	 * </ul>
	 *
	 * @param float $time how much time should we run, if omited nanoserv will enter an endless loop
	 * @param array $user_streams if specified, user streams will be polled along with internal streams
	 * @return array the user streams with pending data
	 * @since 0.9
	 */
	static public function Run($time = NULL, array $user_streams = NULL) {

		$tmp = 0;
		
		$ret = array();
		
		if (isset($time)) {

			if ($time < 0) {
			
				$poll_max_wait = -$time;
				$exit_mt = microtime(true) - $time;

			} else {

				$poll_max_wait = $time;
				$exit = true;
			
			}

		} else {

			$poll_max_wait = 60;
			$exit = false;

		}
		
		do {
		
			$t = microtime(true);

			// Timers

			if (self::$timers_updated) {

				usort(self::$timers, function(Timer $a, Timer $b) { return $a->microtime > $b->microtime; });
				self::$timers_updated = false;

			}
			
			$next_timer_md = NULL;
			
			if (self::$timers) foreach (self::$timers as $k => $tmr) {

				if ($tmr->microtime > $t) {
					
					$next_timer_md = $tmr->microtime - $t;
					break;

				} else if ($tmr->active) {

					$tmr->Deactivate();
					call_user_func($tmr->callback);

				}

				unset(self::$timers[$k]);

			}
			
			if (self::$timers_updated) {

				$t = microtime(true);

				usort(self::$timers, function(Timer $a, Timer $b) { return $a->microtime > $b->microtime; });
				
				foreach (self::$timers as $tmr) {

					if ($tmr->microtime > $t) {
					
						$next_timer_md = $tmr->microtime - $t;
						break;

					}

				}
				
				self::$timers_updated = false;
			
			}
			
			// Write buffers to non blocked sockets

			foreach (self::$write_buffers as $write_buffers) {

				if (!$write_buffers || $write_buffers[0]->socket->blocked || !$write_buffers[0]->socket->connected) continue;

				foreach ($write_buffers as $wb) {

					while ($wb->Waiting_Data() && !$wb->socket->blocked) {
							
						$wb->Write();
						
						if (!$wb->Waiting_Data()) {
								
							array_shift(self::$write_buffers[$wb->socket->id]);
							if (!self::$write_buffers[$wb->socket->id]) self::Free_Write_Buffers($wb->socket->id);

							break;

						}

					}
				
				}

			}
		
			$handler = $so = $write_buffers = $l = $c = $wbs = $wb = $data = $so = NULL;
			
			// Prepare socket arrays

			$fd_lookup_r = $fd_lookup_w = $rfd = $wfd = $efd = array();

			foreach (self::$listeners as $l) if (($l->active) && ((!$l->forking) || (self::$nb_forked_processes <= self::$max_forked_processes))) {
				
				$fd = $l->socket->fd;
				$rfd[] = $fd;
				$fd_lookup_r[(int)$fd] = $l;
			
			}

			$next_conn_timeout_mt = NULL;
			
			foreach (self::$connections as $c) {

				$so = $c->socket;

				if ($so->pending_crypto) {
					
					$cr = $so->Enable_Crypto();

					if ($cr === true) {

						$c->on_Accept();
					
					} else if ($cr === false) {

						$c->on_Connect_Fail(Connection_Handler::FAIL_CRYPTO);
						self::Free_Connection($c);
					
					} else {

						$fd = $so->fd;
						$rfd[] = $fd;
						$fd_lookup_r[(int)$fd] = $c;

					}

				} else if ($so->connected) {
				
					if (!$so->block_reads) {
					
						$fd = $so->fd;
						$rfd[] = $fd;
						$fd_lookup_r[(int)$fd] = $c;

					}
				
				} else if ($so->connect_timeout < $t) {

					$c->on_Connect_Fail(Connection_Handler::FAIL_TIMEOUT);
					self::Free_Connection($c);
				
				} else if ($so->pending_connect) {
				
					$fd = $so->fd;
					$wfd[] = $fd;
					$fd_lookup_w[(int)$fd] = $c;

					if (!$next_conn_timeout_mt || ($so->connect_timeout < $next_conn_timeout_mt)) {

						$next_conn_timeout_mt = $so->connect_timeout;

					}

				}
				
			}

			if (self::$dgram_handlers) foreach (self::$dgram_handlers as $l) if ($l->active) {

				$fd = $l->socket->fd;
				$rfd[] = $fd;
				$fd_lookup_r[(int)$fd] = $l;
			
			}
			
			foreach (self::$write_buffers as $wbs) if ($wbs[0]->socket->blocked) {

				$fd = $wbs[0]->socket->fd;
				$wfd[] = $fd;
				$fd_lookup_w[(int)$fd] = self::$connections[$wbs[0]->socket->id];
			
			}

			if (self::$forked_pipes) foreach (self::$forked_pipes as $fp) {

				$fd = $fp->fd;
				$rfd[] = $fd;
				$fd_lookup_r[(int)$fd] = $fp;
			
			}

			if (isset($user_streams)) {
			
				foreach ((array)$user_streams[0] as $tmp_r) $rfd[] = $tmp_r;
				foreach ((array)$user_streams[1] as $tmp_w) $wfd[] = $tmp_w;
			
			}
			
			// Main select
			
			$wait_mds = array($poll_max_wait);
			if (isset($next_timer_md)) $wait_mds[] = $next_timer_md;
			if (isset($exit_mt)) $wait_mds[] = $exit_mt - $t;
			if (isset($next_conn_timeout_mt)) $wait_mds[] = $next_conn_timeout_mt - $t;
				
			$wait_md = min($wait_mds);
				
			$tv_sec = (int)$wait_md;
			$tv_usec = ($wait_md - $tv_sec) * 1000000;

			if (($rfd || $wfd) && (@stream_select($rfd, $wfd, $efd, $tv_sec, $tv_usec))) {

				foreach ($rfd as $act_rfd) {

					$handler = $fd_lookup_r[(int)$act_rfd];
					$so = $handler->socket;

					if ($handler instanceof Connection_Handler) {

						if ($so->pending_crypto) {
							
							$cr = $so->Enable_Crypto();

							if ($cr === true) {

								$handler->on_Accept();
							
							} else if ($cr === false) {

								$handler->on_Connect_Fail(Connection_Handler::FAIL_CRYPTO);
								self::Free_Connection($handler);
							
							}

						} else if (!$so->connected) {
							
							continue;

						}
						
						$data = $so->Read();

						if (($data === "") || ($data === false)) {

							if ($so->Eof()) {
							
								// Disconnected socket
								
								$handler->on_Disconnect();
								self::Free_Connection($handler);

							}

						} else {

							// Data available
							
							$handler->on_Read($data);
						
						}
					
					} else if ($handler instanceof Datagram_Handler) {
						
						$from = "";
						$data = $so->Read_From($from);

						$handler->on_Read($from, $data);
					
					} else if ($handler instanceof Listener) {

						while ($fd = $so->Accept()) {

							// New connection accepted
							
							$sck = new Socket($fd, $so->crypto_type);

							$hnd = new $handler->handler_classname($handler->handler_options);
							$hnd->socket = $sck;

							if ($handler->forking) {

								$hnd->on_Fork_Prepare();
								
								if (self::Fork() === 0) {

									$hnd->on_Fork_Done();
									
									self::$write_buffers = self::$listeners = array();
									self::$connections = array($sck->id => $hnd);
									self::$forked_connection = $hnd;

									self::Clear_Timers();
									
									if ($sck->Setup()) {
										
										$hnd->on_Accept();

									}

									$handler = $hnd = $sck = $l = $c = $wbs = $wb = $fd_lookup_r = $fd_lookup_w = false;

									break;
									
								} 

								$hnd->on_Fork_Done();

								if (self::$nb_forked_processes >= self::$max_forked_processes) break;
							
							} else {
							
								self::$connections[$sck->id] = $hnd;

								if ($sck->Setup()) {

									$hnd->on_Accept();

								}

							}
						
							$sck = $hnd = NULL;

						}
						
					} else if ($handler instanceof IPC_Socket) {

						while ($ipcm = $handler->Read()) {
						
							if ((!$ipcq = unserialize($ipcm)) || (!is_object($o = self::$shared_objects[$ipcq["oid"]]))) continue;

							switch ($ipcq["action"]) {

								case "G":
								$handler->Write(serialize($o->$ipcq["var"]));
								break;

								case "S":
								$o->$ipcq["var"] = $ipcq["val"];
								break;

								case "C":
								Shared_Object::$caller_pid = $handler->pid;
								$handler->Write(serialize(call_user_func_array(array($o, $ipcq["func"]), $ipcq["args"])));
								break;
							
							}

						}
					
						$o = $ipcq = $ipcm = NULL;
						
					} else if (!isset($handler)) {

						// User stream

						$ret[0][] = $act_rfd;
					
					}

				}

				foreach ($wfd as $act_wfd) {
					
					$handler = $fd_lookup_w[(int)$act_wfd];
					$so = $handler->socket;
					
					if (!isset($handler)) {

						// User stream

						$ret[1][] = $act_wfd;
					
					} else if ($so->connected) {

						// Unblock buffered write
						
						if ($so->Eof()) {

							$handler->on_Disconnect();
							self::Free_Connection($handler);
						
						} else {
						
							$so->blocked = false;

						}

					} else if ($so->pending_connect) {
					
						// Pending connect

						if ($so->Eof()) {

							$handler->on_Connect_Fail(Connection_Handler::FAIL_CONNREFUSED);
							self::Free_Connection($handler);
						
						} else {

							$so->Setup();
							$so->connected = true;
							$so->pending_connect = false;
							$handler->on_Connect();

						}

					}
				
				}
				
			}

			if (self::$nb_forked_processes && !self::$child_process) while ((($pid = pcntl_wait($tmp, WNOHANG)) > 0) && self::$nb_forked_processes--) unset(self::$forked_pipes[$pid]);
			
			if ($ret) {

				return $ret;
			
			} else if (isset($exit_mt)) {

				$exit = $exit_mt <= $t;
			
			}
		
		} while (!$exit);
	
	}

}

?>
