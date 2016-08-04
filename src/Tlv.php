<?php 

require_once 'Tea.php';
require_once 'Coder.php';

class Tlv
{
	protected static function tlvLen($tlv, $n = 2)
	{
		return Coder::num2Hexstr(strlen($tlv)/2, $n).$tlv;
	}

	protected static function headerTlv($head, $tlv) {
		return Coder::trim($head).$tlv;
	}

	public static function tlv1($uin, $server_time) {
		$tlv = Coder::trim('00 01').Coder::genBytesHexstr(4).$uin.$server_time.Coder::trim('00 00 00 00 00 00');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('00 01', $tlv);
	}


	public static function tlv2($verifyCode, $verifyToken1) {
		$tlv = self::tlvLen($verifyCode, 4).self::tlvLen($verifyToken1);
		$tlv = self::tlvLen($tlv).$tlv;
		return self::headerTlv('00 02', $tlv);
	}

	public static function tlv8() {
								  #request_global._local_id
		$tlv = Coder::trim('00 00 00 00 08 04               00 00');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('00 08', $tlv);
	}


	public static function tlv18($uin) {
		$tlv = Coder::trim('00 01 00 00 06 00 00 00 00 10 00 00 00 00').$uin.Coder::trim('00 00 00 00');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('00 18', $tlv);
	}

	public static function tlv100() {
		$tlv = Coder::trim('00 01 00 00 00 05 00 00 00 10 20 02 9F 54 00 00 00 00 02 1E 10 E0');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 00', $tlv);
	}

	public static function tlv104($verifyToken2) {
		$tlv = self::tlvLen($verifyToken2);
		return self::headerTlv('01 04', $tlv);
	}
	public static function tlv106($uin, $server_time, $pwdMd5, $tgtKey, $imei, $appId, $pwdKey) {

		$tlv = Coder::trim('00 03');
		$tlv .= Coder::genBytesHexstr(4);
		$tlv .= Coder::trim('00 00 00 05 00 00 00 10 00 00 00 00 00 00 00 00');
		$tlv .= $uin;
		$tlv .= $server_time;
		$tlv .= Coder::trim('00 00 00 00 01');
		$tlv .= $pwdMd5;
		$tlv .= $tgtKey;
		$tlv .= Coder::trim('00 00 00 00 01');
		$tlv .= $imei;
		$tlv .= $appId;
		$tlv .= Coder::trim('00 00 00 01 00 00');
		$tlv = Tea::enteaHexstr($tlv, $pwdKey);
		
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 06', $tlv);
	}

	public static function tlv107() {
		$tlv = Coder::trim('00 00 00 00 00 01');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 07', $tlv);
	}

	public static function tlv109($imei) {
		$tlv = self::tlvLen($imei);
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 09', $tlv);
	}

	public static function tlv116() {
		$tlv = Coder::trim('00 00 01 FF 7C 00 01 04 00 00');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 16', $tlv);
	}

	public static function tlv124($os_type, $os_version, $network_type, $sim_operator_name, $apn) {
		$tlv = self::tlvLen($os_type);
		$tlv .= self::tlvLen($os_version);
		$tlv .= self::tlvLen($network_type);
		$tlv .= self::tlvLen($sim_operator_name);
		$tlv .= Coder::trim('00 00');
		$tlv .= self::tlvLen($apn);
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 24', $tlv);
	}

	public static function tlv128($device, $imei, $device_product) {
		$tlv = Coder::trim('00 00 01 01 00 11 00 00 00');
		$tlv .= self::tlvLen($device);
		$tlv .= self::tlvLen($imei);
		$tlv .= self::tlvLen($device_product);
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 28', $tlv);
	}

	public static function tlv144($tgtKey, $imei, $os_type, $os_version, $network_type, $sim_operator_name, $apn, $device, $device_product) {
		$tlv = Coder::trim('00 04');
		$tlv.= self::tlv109($imei);
		$tlv.=self::tlv124($os_type, $os_version, $network_type, $sim_operator_name, $apn);
		$tlv.=self::tlv128($device, $imei, $device_product);
		$tlv.=self::tlv16e($device);
		$tlv = Tea::enteaHexstr($tlv, $tgtKey);
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 44', $tlv);
	}

	public static function tlv141($sim_operator_name, $network_type, $apn) {
		$tlv = Coder::trim('00 01');
		$tlv.=self::tlvLen($sim_operator_name);
		$tlv.=self::tlvLen($network_type);
		$tlv.=self::tlvLen($apn);
		$tlv=self::tlvLen($tlv);
		return self::headerTlv('01 41', $tlv);
	}

	public static function tlv142($package_name) {
		$tlv = self::tlvLen($package_name, 4);
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 42', $tlv);
	}

	public static function tlv145($imei) {
		$tlv = self::tlvLen($imei);
		return self::headerTlv('01 45', $tlv);
	}

	public static function tlv147() {
		//                                    35 2E 38 2E 30 #request_global._apk_v = 5.8.0
		//                                    					   A6 B7 45 BF 24 A2 C2 77 52 77 16 F6 F3 6E B6 8D #request_global._apk_sig
		$tlv = Coder::trim('00 00 00 10 00 05 35 2E 38 2E 30 00 10 A6 B7 45 BF 24 A2 C2 77 52 77 16 F6 F3 6E B6 8D');
  		$tlv = self::tlvLen($tlv);
  		return self::headerTlv('01 47', $tlv);
	}

	public static function tlv154($seq) {
		$tlv = Coder::num2Hexstr($seq, 4); # ???
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 54', $tlv);
	}

	public static function tlv16b() {
		$tlv = Coder::trim('00 02 00 0B 67 61 6D 65 2E 71 71 2E 63 6F 6D 00 0B 67 61 6D 65 2E 71 71 2E 63 6F 6D');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 6B', $tlv);
	}

	public static function tlv16e($device) {
		$tlv = self::tlvLen($device);
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 6E', $tlv);
	}

	public static function tlv177() {
		$tlv = Coder::trim('01 55 A3 23 2E 00 07 35 2E 34 2E 30 2E 37');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 77', $tlv);
	}

	public static function tlv187() {
		$tlv = Coder::trim('F9 03 BA FF 80 D5 BA AC DC EA 9C 16 49 6F 53 83');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 87', $tlv);
	}

	public static function tlv188() {
		$tlv = Coder::trim('3F D1 F5 BA 24 67 56 F3 97 87 49 AE 1D 67 76 EE');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 88', $tlv);
	}

	public static function tlv191() {


		$tlv = Coder::trim('01');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 91', $tlv);

	}

	public static function tlv194() {

		$tlv = Coder::trim('65 68 D4 A4 FA CA 6E 78 B3 6B 07 40 C2 71 A8 6E');
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('01 94', $tlv);
	}

	public static function tlv202($wifi_name) {

		$tlv = Coder::trim('00 10 F5 AC 6C 03 0C 31 AE 5C 26 2E BE 49 86 23 65 1E');
		$tlv .= self::tlvLen($wifi_name);
		$tlv = self::tlvLen($tlv);
		return self::headerTlv('02 02', $tlv);
	}

}

