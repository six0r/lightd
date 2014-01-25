#!/usr/local/bin/php
<?php

/*

lightd - a simple HTTP gateway for the lifx binary protocol

Copyright (C) 2014 Vincent Negrier aka. sIX <six at aegis-corp.org>

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 

*/

namespace Lightd;

const VERSION = "0.9.0";

const LIFX_HOST = "lifx";
const LIFX_PORT = 56700;

const API_LISTEN_ADDR = "0.0.0.0";
const API_LISTEN_PORT = 5439;

require_once "nanoserv/nanoserv.php";
require_once "nanoserv/handlers/HTTP/Server.php";
require_once "lifx.php";

use Nanoserv\HTTP\Server as HTTP_Server;
use Nanoserv\Core as Nanoserv;

use Lightd\Drivers\Lifx\Packet as Lifx_Packet;
use Lightd\Drivers\Lifx\Handler as Lifx_Handler;
use Exception;

class Light {
	
	static public $all = [];

	public $id;
	public $label;
	public $tags;
	public $state_ts;

	public $rgb;
	public $power;
	public $extra;

	public function __construct($id = null, $label = null) {
		$this->id = $id;
		$this->label = $label;
	}
	
	static public function Get_All() {
		return array_values(self::$all);
	}
	
	static public function Get_By_Name($label) {
		foreach (self::$all as $l) {
			if ($l->label === $label) {
				return $l;
			}
		}
		throw new Exception("light not found: {$label}");
	}
	
	static public function Register(self $l) {
		self::$all[$l->id] = $l;
		log("new bulb registered: {$l->label}");
	}

	static public function Dump() {
		foreach (self::$all as $l) {
			log($l->label . " " . ($l->power ? "on" : "off") . " " . $l->rgb . " @ " . $l->extra["kelvin"] . "K (" . date("Ymd:His", $l->state_ts) . ")");
		}
	}

	public function Set_Power($power = true) {
		$GLOBALS["lifx"]->Set_Power($power, $this->id);
	}

	public function Set_Color($rgb, array $extra = []) {
		$GLOBALS["lifx"]->Set_Color($rgb, $extra, $this->id);
	}

}

class Lifx_Client extends Lifx_Handler {
	public function on_Connect() {
		log("connected to " . LIFX_HOST);
		parent::on_Connect();
	}
	public function on_Discover(Lifx_Packet $pkt) {
		log("found gateway bulb at {$pkt->gateway_mac}");
		parent::on_Discover($pkt);
	}
	public function on_Packet(Lifx_Packet $pkt) {
		// var_dump($pkt);
	}
	public function on_Light_State(Light $l) {
		if (isset(Light::$all[$l->id])) {
			$rl = Light::$all[$l->id];
		} else {
			$rl = new Light($l->id, $l->label);
			Light::Register($rl);
		}
		$rl->state_ts = time();
		$rl->id = $l->id;
		$rl->label = $l->label;
		$rl->tags = $l->tags;
		$rl->rgb = $l->rgb;
		$rl->power = $l->power;
		$rl->extra = $l->extra;
	}
}

class API_Server extends HTTP_Server {
	public function on_Request($url) {
		try {
			log("[{$this->socket->Get_Peer_Name()}] API {$url}");
			$args = explode("/", ltrim(urldecode($url), "/"));
			$cmd = array_shift($args);
			switch ($cmd) {
				
				case "power":
				switch ($args[0]) {
					case "on":
					$power = true;
					break;
					case "off":
					$power = false;
					break;
				}
				if (!isset($power)) {
					throw new Exception("invalid argument '{$args[0]}'");
				}
				if ($args[1]) {
					Light::Get_By_Name($args[1])->Set_Power($power);
				} else {
					$GLOBALS["lifx"]->Set_Power($power);
				}
				break;

				case "color":
				$rgb = "#" . strtok($args[0], "K");
				$kelvin = strtok("")
				or $kelvin = 6500;
				if ($args[1]) {
					Light::Get_By_Name($args[1])->Set_Color($rgb, [ "kelvin" => $kelvin ]);
				} else {
					$GLOBALS["lifx"]->Set_Color($rgb, [ "kelvin" => $kelvin ]);
				}
				break;

				case "state":
				if ($args[0]) {
					return json_encode(Light::Get_By_Name($args[0]), JSON_PRETTY_PRINT);
				} else {
					return json_encode(Light::Get_All(), JSON_PRETTY_PRINT);
				}
				break;
				
				case "pattern":
				if (!isset($args[0])) {
					return json_encode([ 
						"current" => $GLOBALS["current_pattern"],
						"ts" => $GLOBALS["current_pattern_ts"],
					]);
				} else if (!isset($GLOBALS["patterns"][$args[0]])) {
					throw new Exception("unknown pattern '{$args[0]}'");
				}
				if ($args[1]) {
					$fade = $args[1];
				}
				foreach ($GLOBALS["patterns"][$args[0]] as $bname => $bdata) {
					$l = Light::Get_By_Name($bname);
					$l->Set_Power($bdata["power"]);
					if ($bdata["rgb"]) {
						$rgb = "#" . $bdata["rgb"];
						$l->Set_Color($rgb, [ 
							"kelvin" => $bdata["kelvin"],
							"fade" => $fade,
						]);
					}
				}
				$GLOBALS["current_pattern"] = $args[0];
				$GLOBALS["current_pattern_ts"] = time();
				break;

			}
			return "ok";
		} catch (Exception $e) {
			$this->Set_Response_Status(400);
			return "error: {$e->getMessage()}";
		}
	}
}

function log($msg) {
	echo date("Ymd:His") . " " . $msg . "\n";
}

log("lightd/" . VERSION . " (c) 2014 by sIX / aEGiS <six@aegis-corp.org>");

$patterns = [];
$current_pattern = "off";
$current_pattern_ts = 0;

foreach (parse_ini_file(dirname(__FILE__) . DIRECTORY_SEPARATOR . "patterns.ini", true, INI_SCANNER_RAW) as $pname => $bulbs) {
	$bdata = [];
	foreach ($bulbs as $bname => $str) {
		$power = ($str !== "off");
		$bcmd = [ "power" => $power ];
		if ($power) {
			if (preg_match('/#([0-9a-fA-F]{6})/', $str, $res)) {
				$bcmd["rgb"] = $res[1];
			}
			if (preg_match('/([0-9]+)K/', $str, $res)) {
				$bcmd["kelvin"] = $res[1];
			}
		}
		$bdata[$bname] = $bcmd;
	}
	$patterns[$pname] = $bdata;
}

log("loaded " . count($patterns) . " patterns");

$lifx = Nanoserv::New_Connection("tcp://" . LIFX_HOST . ":" . LIFX_PORT, __NAMESPACE__ . "\\Lifx_Client");
$lifx->Connect();

Nanoserv::Run(1);

if (!$lifx->socket->connected) {
	log("cannot connect");
	exit(1);
}

Nanoserv::New_Listener("tcp://" . API_LISTEN_ADDR . ":" . API_LISTEN_PORT, __NAMESPACE__ . "\\API_Server")->Activate();
log("API server listening on port " . API_LISTEN_PORT);

$last_refresh_ts = time();

while (true) {
	Nanoserv::Run(-1);
	$t = time();
	if ($lifx->must_reconnect) {
		log("lost connection, trying to reconnect ...");
		sleep(3);
		$lifx = Nanoserv::New_Connection("tcp://" . LIFX_HOST . ":" . LIFX_PORT, __NAMESPACE__ . "\\Lifx_Client");
		$lifx->Connect();
		Nanoserv::Run(-1);
	} else {
		if (($last_refresh_ts + 2) < $t) {
			$lifx->Refresh_States();
			$last_refresh_ts = $t;
		}
	}
}

?>