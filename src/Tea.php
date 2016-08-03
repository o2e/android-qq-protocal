<?php 

/**
* 
*/
class Tea
{
	public static function xor($a, $b)
	{
		$op = 0xffffffff;
		$a = unpack('L*', substr($a, 0, 8));
		$b = unpack('L*', substr($b, 0, 8));
		return pack('LL', ($a[1] ^ $b[1]) & $op, ($a[2] ^ $b[2]) & $op);
	}

	public static function code($v, $k)
	{
		$n = 16;
		$op = 0xffffffff;
		$delta = 0x9e3779b9;
		$k = unpack('L*', substr($k, 0, 16));
		$v = unpack('L*', substr($v, 0, 8));
		$s = 0;
		for ($i=0; $i < $n; $i++) { 
			$s+=$delta;
			$v[1]+=($op&($v[2]<<4)) + $k[1] ^ $v[2] + $s ^ ($op & ($v[2]>>5)) + $k[2];
			$v[1] &= $op;
			$v[2]+=($op&($v[1]<<4)) + $k[3] ^ $v[1] + $s ^ ($op & ($v[1]>>5)) + $k[4];
			$v[2]&=$op;
		}
		$r = pack('LL', $v[1], $v[2]);
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
		$v = unpack('L*', $v);
		$k = unpack('L*', $k);
		$delta = 0x9E3779B9;
		$s = ($delta << 4) & $op;
		for ($i=0; $i < $n; $i++) { 
            $v[2] -= (($v[1]<<4)+$k[3]) ^ ($v[1]+$s) ^ (($v[1]>>5) + $k[4]);
            $v[2] &= $op;
            $v[1] -= (($v[2]<<4)+$k[1]) ^ ($v[2]+$s) ^ (($v[2]>>5) + $k[2]);
            $v[1] &= $op;
            $s -= $delta;
            $s &= $op;
		}
		return pack('LL', $v[1], $v[2]);
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







// $hexstr = '000000700000000120029f5420029f54010000000000000000000000000000040000001177746c6f67696e2e6c6f67696e00000008f9838d80000000133836343131363139353739373932320000000400227c3436303030363230323231373439317c41352e382e302e313537313538000002d80202d41f4108100001023bd5ac0307000000000200000000000000000101e6104301bad95d380fcb532d367dc6fb01020019031987BFF9D37F8F779416AFB21CF1BABEF9B1392E83EC52C96dc1628ac1fcdc50bc902d13fe8e1f5e4e2f247e863497b3d1d4c289908a82190b61ba8ec0dbee77ee10c5ee72fb12a86dbdc7dd5b57b735331d99a38eb1aff4db44c92273bd2b6fc2aca48467f4f67483362c285aa57f5c1c56eb0d364523466b673569f5468e2d08804335f69c553a00396fa65c6905faf95017e437339ef5e5a30df3d7b452da82dc2054524cb8c38f312eb33c4775ea1fe89e55f6e37f6a2d870164da104b3a4c946e7ee9201adf8a42e29a88b64bb65e22ee51dd035c04e0444886b58d21634e1bdf0816e915ca262182cc206881283284aa59b47b033ae092ae56d482edb1075260d90910456dab79d85b0aeedc55b552094f47e14647cc1ce891e81bb1cb801c92ab9f9d3dc8c04567d277c57e2b9898674ef14617206f97d8ca7724e04e501b12f4cf892ce95017f714dbb56ea9b79e35ebe032e1b5714e4d1001538e997141a8c1d023130ccb7e609be153f93ce77fb54029e9a48e24e3db7c389e8442bf77939a8d890b1fa8dd812163d324be839ab840fe19416e6d73f65cbfd8b89c173e28d9ad93b5bbb6a4749787dbeafe0d7293ddd9f5fa5211975fe2e5d14c45875bcbcfdccfd7c5e5ace11811ec349d07c6ca539dd84d392e3fb5602234947521b47327c5c99c438bab4deafa993b16c11b8686c1d884cc72071c6e672d5aa80d7949f614375a3386bd740873a0465ab4df75011868346caead310d4edaa297d381b838a541a4628c3b9480b75e16c444ed36fd3c0b320103f7738be6d86108bf620fa9691f2351865387de96b20485ff4e877efa36e17e54c41c44cf8f9df3a11afaaf9839834059250c92df521b4041f5791534a85ccac91a6f30f7fe7d23b77c3d4937688f20506e6b9b541de3b86d8844c3b0da6453c1b114f20e3aa86103';
// $key = '00000000000000000000000000000000';


// var_dump(Tea::deteaHexstr(
// 	Tea::enteaHexstr($hexstr, $key)
// 	, $key) === $hexstr);




