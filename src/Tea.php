<?php 



class Tea
{
	public static function xor($a, $b)
	{
		$op = 0xffffffff;
		$a = unpack('Na1/Na2', substr($a, 0, 8));
		$b = unpack('Nb1/Nb2', substr($b, 0, 8));
		$ret = pack('NN', ($a['a1'] ^ $b['b1']) & $op, ($a['a2'] ^ $b['b2']) & $op);
		return $ret;
	}

	public static function code($v, $k)
	{
		$n = 16;
		$op = 0xffffffff;
		$delta = 0x9e3779b9;
		$k = unpack('Nk1/Nk2/Nk3/Nk4', substr($k, 0, 16));
		$v = unpack('Nv1/Nv2', substr($v, 0, 8));
		$s = 0;
		for ($i=0; $i < $n; $i++) {
			$s+=$delta;
			$v['v1'] += ($op &($v['v2']<<4))+ $k['k1'] ^ $v['v2']+ $s ^ ($op&($v['v2']>>5)) + $k['k2'];
			$v['v1'] &= $op;
			$v['v2']+=($op&($v['v1']<<4)) + $k['k3'] ^ $v['v1'] + $s ^ ($op & ($v['v1']>>5)) + $k['k4'];
			$v['v2']&=$op;
		}
		$r = pack('NN', $v['v1'], $v['v2']);
		return $r;
	}

	public static function encrypt($v, $key)
	{
		$END_CHAR = "\0";
		$FILL_N_OR = 0xF8;
		$vl = strlen($v);
		$filln = (8-($vl+2))%8 + 2;
		if($filln <= 0) {
			$filln = 8 + $filln;
		}
		$fills = '';
		for ($i=0; $i < $filln; $i++) { 
			$fills .= chr(mt_rand(0, 255));
		}
		$v = chr(($filln - 2) | $FILL_N_OR) . $fills . $v . str_repeat($END_CHAR, 7);
		$tr = str_repeat("\0", 8);
		$to = $tr;
		$r = "";
		$o = $to;
		for ($i=0; $i < strlen($v); $i+=8) {
			$o = self::xor(substr($v, $i, 8), $tr);
			$tr = self::xor(self::code($o, $key), $to);
			$to = $o;
			$r .= $tr;
		}
		return $r;
	}

	public static function decipher($v, $k)
	{
		$n = 16;
		$op = 0xffffffff;
		$k = unpack('Nk1/Nk2/Nk3/Nk4', substr($k, 0, 16));
		$v = unpack('Nv1/Nv2', substr($v, 0, 8));
		$delta = 0x9E3779B9;
		$s = ($delta << 4) & $op;
		for ($i=0; $i < $n; $i++) { 
            $v['v2'] -= (($v['v1']<<4)+$k['k3']) ^ ($v['v1']+$s) ^ (($v['v1']>>5) + $k['k4']);
            $v['v2'] &= $op;
            $v['v1'] -= (($v['v2']<<4)+$k['k1']) ^ ($v['v2']+$s) ^ (($v['v2']>>5) + $k['k2']);
            $v['v1'] &= $op;
            $s -= $delta;
            $s &= $op;
		}
		return pack('NN', $v['v1'], $v['v2']);
	}

	public static function decrypt($v, $key)
	{
		$l = strlen($v);
		$prePlain = self::decipher($v, $key);
		$pos = (ord($prePlain[0]) & 0x07) + 2;
		$r = $prePlain;
		$preCrypt = substr($v, 0, 8);
		for ($i=8; $i < $l; $i+=8) {
			$x = self::xor(self::decipher(self::xor(substr($v, $i, 8), $prePlain), $key), $preCrypt);
			$prePlain = self::xor($x, $preCrypt);
			$preCrypt = substr($v, $i, 8);
			$r .= $x;
		}

		if(substr($r, -7) != str_repeat("\0", 7)) {
			return null;
		}
		return substr($r, $pos + 1, strlen($r)-7-$pos-1);
	}

	/**
	 * [entea_hexstr description]
	 * @param  [type] $data [description] 8
	 * @param  [type] $key  [description] 32
	 * @return [type]       [description]
	 */
	public static function enteaHexstr($data, $key)
	{
		return bin2hex(self::encrypt(hex2bin($data), hex2bin($key)));
	}

	/**
	 * [detea_hexstr description]
	 * @param  [type] $data [description] 8
	 * @param  [type] $key  [description] 32
	 * @return [type]       [description]
	 */
	public static function deteaHexstr($data, $key)
	{
		return bin2hex(self::decrypt(hex2bin($data), hex2bin($key)));
	}
}
