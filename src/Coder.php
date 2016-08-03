<?php 

class Coder
{
	public static function trim($str)
	{
		return strtolower(str_replace(' ', '', $str));
	}

	public static function num2Hexstr($num, $n = 1)
	{
		$num = dechex($num);
		return str_repeat('0', 2 * $n - strlen($num)) . $num;
	}

	public static function numlist2Hexstr($list, $n = 1, $s = '')
	{
		return join($s, array_map(function($i) use ($n) {
			return self::num2Hexstr($i);
		}, $list));
	}

	public static function genBytesHexstr($m, $n = 1, $s = '')
	{
		return self::numlist2Hexstr(array_map(function() {
			return mt_rand(0, 255);
		}, range(0, $m - 1)), $n, $s);
	}

	public static function qqNumber2Hexstr($qqNumber)
	{
        $data = dechex(intval($qqNumber));
        return str_repeat('0', 8 - strlen($data)) . $data;
	}

	public static function hashQqPasswordHexstr($qqNumber, $qqPassword)
	{
		return md5(hex2bin(md5($qqPassword)) . hex2bin('00000000') . hex2bin(self::qqNumber2Hexstr($qqNumber)));
	}

	public static function ip2Long($ip)
	{
		return strtoupper(dechex(ip2long('45.112.249.58')));
	}

	public static function long2Ip($num)
	{
		if(is_string($num)) {
			$num = hexdec($num);
		}
		return long2ip($num);
	}

	public static function ip2Hexstr($ip)
	{
		return strtolower(self::ip2Long($ip));
	}

	public static function hexstr2Ip($data)
	{
		return self::long2Ip(hexdec($data));
	}

	public static function hexstr2Hexlist($str)
	{
		$res = [];
		for ($i=0; $i < strlen($str); $i+=2) { 
			$res[] = $str[$i] . $str[$i+1];
		}
		return $res;
	}

	public static function hexstr2Hexstream($str)
	{
		return join('', array_map(function($v) {
			return chr(hexdec($v));
		}, self::hexstr2Hexlist($str)));
	}

	public static function str2Hexstr($str)
	{
		return bin2hex($str);
	}

	public static function hexstr2Str($str)
	{
		return hex2bin($str);
	}

	public static function hexstr2Num($str)
	{
		return hexdec($str);
	}
}

