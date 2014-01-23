<?php

/**
 *
 * nanoserv handlers - HTTP service handler
 * 
 * Copyright (C) 2004-2010 Vincent Negrier aka. sIX <six@aegis-corp.org>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA * 
 *
 * @package nanoserv
 * @subpackage Handlers
 */

namespace Nanoserv\HTTP;

/**
 * Require the nanoserv core
 */
require_once "nanoserv/nanoserv.php";

/**
 * HTTP Service handler class
 *
 * @package nanoserv
 * @subpackage Handlers
 */
abstract class Server extends \Nanoserv\Connection_Handler {

	/**
	 * Server string
	 */
	const SERVER_STRING = "";

	/**
	 * Max request length
	 */
	const MAX_REQUEST_LENGTH = 1048576;
	
	/**
	 * Default content type
	 */
	const DEFAULT_CONTENT_TYPE = "text/html";
	
	/**#@+
	 * Compression options
	 * @var int
	 */
	const COMPRESS_AUTO = 1;
	const COMPRESS_OFF = 2;
	/**#@-*/
	
	/**
	 * Response status codes and strings
	 */
	private $STATUS_CODES = array(100 => "100 Continue",
			200 => "OK",
			201 => "Created",
			204 => "No Content",
			206 => "Partial Content",
			300 => "Multiple Choices",
			301 => "Moved Permanently",
			302 => "Found",
			303 => "See Other",
			304 => "Not Modified",
			307 => "Temporary Redirect",
			400 => "Bad Request",
			401 => "Unauthorized",
			403 => "Forbidden",
			404 => "Not Found",
			405 => "Method Not Allowed",
			406 => "Not Acceptable",
			408 => "Request Timeout",
			410 => "Gone",
			413 => "Request Entity Too Large",
			414 => "Request URI Too Long",
			415 => "Unsupported Media Type",
			416 => "Requested Range Not Satisfiable",
			417 => "Expectation Failed",
			500 => "Internal Server Error",
			501 => "Method Not Implemented",
			503 => "Service Unavailable",
			506 => "Variant Also Negotiates");
	
	/**
	 * Request headers
	 * @var array
	 */
	protected $request_headers = array();
	
	/**
	 * Request method
	 * @var string
	 */
	protected $request_method = "";
	
	/**
	 * Request protocol
	 * @var string
	 */
	protected $request_protocol = "";
	
	/**
	 * Request content (raw POST data)
	 * @var string
	 */
	protected $request_content = "";
	
	/**
	 * Compress option
	 * @var int
	 */
	protected $compress = self::COMPRESS_OFF;

	/**
	 * Compression level
	 * @var int
	 */
	protected $compress_level = 3;
	
	/**
	 * Request buffer
	 * @var string
	 */
	private $request_buffer = "";
	
	/**
	 * Response headers
	 * @var array
	 */
	private $response_headers = array();
	
	/**
	 * Response content type
	 * @var string
	 */
	private $response_content_type;
	
	/**
	 * Response status code
	 * @var int
	 */
	private $response_status = 200;
	
	public function __construct() {

		$this->response_content_type = static::DEFAULT_CONTENT_TYPE;

	}
	
	protected function Handle_Request($url) {

		$this->Send_Response($this->on_Request($url));
	
	}
	
	final public function on_Read($data) {

		$this->request_buffer .= $data;

		while ($this->request_buffer) {
		
			if (($p = strpos($this->request_buffer, "\r\n\r\n")) !== false) {

				$hdrs = substr($this->request_buffer, 0, $p);
				$cnt = substr($this->request_buffer, $p + 4);
			
			} else if (($p = strpos($this->request_buffer, "\n\n")) !== false) {

				$hdrs = substr($this->request_buffer, 0, $p);
				$cnt = substr($this->request_buffer, $p + 2);
			
			} else {

				if (isset($this->request_buffer[static::MAX_REQUEST_LENGTH])) {

					$this->Set_Response_Status(414);
					$this->Send_Response("Request too large");
				
				} else {
				
					return;

				}

			}

			// Extract first line

			list($this->request_method, $url, $this->request_protocol) = explode(" ", strtok($hdrs, "\r\n"));

			// And process headers
			
			$hdrs = explode("\n", trim(strtok("")));
			$tmp = array();

			foreach ($hdrs as $hdr) {
				
				$k = strtoupper(strtok($hdr, ":"));
				$tmp[$k] = trim(strtok(""));
			
			}

			$this->request_headers = $tmp;

			if ((isset($this->request_headers["CONTENT-LENGTH"])) && ($cl = $this->request_headers["CONTENT-LENGTH"])) {

				if ($cl > static::MAX_REQUEST_LENGTH) {

					$this->Set_Response_Status(413);
					$this->Send_Response("Request too large");
				
				} else if (strlen($cnt) < $cl) {
				
					return;

				}

				$this->request_content = substr($cnt, 0, $cl);
				$this->request_buffer = ltrim(substr($cnt, $cl));

			} else {
			
				$this->request_content = "";
				$this->request_buffer = $cnt;

			}

			if (($this->request_protocol !== "HTTP/1.0") && ($this->request_protocol !== "HTTP/1.1")) {

				$this->Set_Response_Status(400);
				$this->Send_Response("Bad Request");
			
			} else {

				$this->Handle_Request($url);

			}

		}
	
	}

	/**
	 * Event called on HTTP request
	 *
	 * the string returned by on_Request() will be sent back as the HTTP response
	 *
	 * @param string $url
	 * @return string
	 */
	abstract public function on_Request($url);

	/**
	 * Add HTTP header to the response
	 *
	 * @param string $header
	 */
	public function Add_Header($header) {

		$this->response_headers[] = $header;
	
	}
	
	/**
	 * Set response content type
	 *
	 * @param string $content_type
	 */
	public function Set_Content_Type($content_type) {

		$this->response_content_type = $content_type;

	}
	
	/**
	 * Set HTTP response status code
	 *
	 * 200 = OK, 403 = Forbidden, 404 = Not found, ...
	 *
	 * @param int $code
	 */
	public function Set_Response_Status($code = 200) {

		$this->response_status = $code;
	
	}
	
	/**
	 * Set compression option
	 *
	 * @param int $option
	 */
	public function Set_Compression($opt = self::COMPRESS_AUTO) {

		switch ($opt) {

			case self::COMPRESS_AUTO:	$this->compress = extension_loaded("zlib") ? self::COMPRESS_AUTO : self::COMPRESS_OFF;		break;
			case self::COMPRESS_OFF:	$this->compress = $opt;																		break;
			default:					throw new \Nanoserv\Exception("invalid compress option '{$opt}'");

		}
	
	}
	
	/**
	 * Compress a response if possible and needed
	 *
	 * @param string &$data
	 * @param string &$encoding
	 * @return bool
	 */
	protected function Compress_Response(&$data, &$encoding = NULL) {

		$methods = array(	"deflate"	=> "gzdeflate",
							"gzip"		=> "gzencode",
							"compress"	=> "gzcompress");
		
		foreach ($methods as $m => $func) {

			if (strpos($this->request_headers["ACCEPT-ENCODING"], $m) !== false) {

				$method = $m;
				break;

			}

		}
	
		if (!isset($method)) return false;

		$data = $func($data, $this->compress_level);
		$encoding = $method;

		return true;
	
	}
	
	/**
	 * Send HTTP response back to client
	 *
	 * This method is only invoked by the on_Read() handler
	 *
	 * @param string $data
	 */
	protected function Send_Response($data, $length = null) {

		$keep = isset($this->request_headers["CONNECTION"]) ? (strtoupper($this->request_headers["CONNECTION"]) === "KEEP-ALIVE") : false;
		
		$resp = "HTTP/1.1 " . (int)$this->response_status . " " . $this->STATUS_CODES[$this->response_status] . "\r\n"
			  . "Date: " . gmdate("D, d M Y H:i:s T") . "\r\n"
		      . "Server: " . (static::SERVER_STRING ? static::SERVER_STRING : "nanoserv/2.1.2-dev") . "\r\n"
		      . "Content-Type: " . $this->response_content_type . "\r\n"
		      . "Content-Length: " . (isset($length) ? $length : strlen($data)) . "\r\n"
			  . "Connection: " . ($keep ? "Keep-Alive" : "Close") . "\r\n";

		if (($this->compress !== self::COMPRESS_OFF) && $this->Compress_Response($data, $encoding)) $resp .= "Content-Encoding: " . $encoding . "\r\n";
		if ($this->response_headers) $resp .= implode("\r\n", $this->response_headers) . "\r\n";

		$resp .= "\r\n" . $data;
		
		$this->Write($resp, ($keep ? false : array($this, "Disconnect")));

		$this->response_content_type = static::DEFAULT_CONTENT_TYPE;
		$this->response_headers = array();
		$this->response_status = 200;

	}

}

/**
 * HTTP Asynchronous service handler class
 *
 * @package nanoserv
 * @subpackage Handlers
 */
abstract class Async_Server extends Server {

	protected function Handle_Request($url) {

		$this->on_Request($url);
	
	}

}

?>