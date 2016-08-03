<?php 

/**
* 	
*/
class HexPacket
{

	protected $cur;
	protected $data;
	protected $length;

	public function __construct($data)
	{
		$this->data = $data;
		$this->cur = 0;
		$this->length = strlen($data);
	}

	public function shl($n)
	{
		$n *= 2;
		if($n > $this->cur)
			$n = $this->cur;
		$old = $this->cur;
		$this->cur -= $n;
		return substr($this->data, $this->cur, $old - $this->cur) ?: '';
	}

	public function shr($n)
	{
		$n *= 2;
		if($n + $this->cur > $this->length)
			$n = $this->legnth - $this->cur;
		$old = $this->cur;
		$this->cur += $n;
		return substr($this->data, $old, $this->cur - $old) ?: '';
	}

	public function remain_n()
	{
		return ($this->length - $this->cur) / 2;
	}

	public function remain($rn = 0)
	{
		return $this->shr($this->remain_n() - $rn);
	}

	public function len()
	{
		return $this->length;
	}

	public function cur_byte()
	{
		return substr($this->data, $this->cur, 2) ?: '';
	}
}



