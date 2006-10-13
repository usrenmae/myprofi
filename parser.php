<?php
class extractor
{
	const CHUNK_SIZE = 10240; // bytes

	protected $fp;

	protected $cur_chunk;

	public function __construct($fp)
	{
		$this->fp = $fp;
	}

	protected function read_chunk()
	{
		if (feof($this->fp))
		{
			return false;
		}

		$this->cur_chunk .= fread($this->fp, self::CHUNK_SIZE);
		return true;
	}

	public function get_line()
	{
		while (false === ($pos = strpos($this->cur_chunk,"\n")))
		{
			if (!$this->read_chunk())
			{
				$pos = strlen($this->cur_chunk)-1;
				break;
			}
		}

		$line = substr($this->cur_chunk, 0, $pos+1);
		$this->cur_chunk = substr($this->cur_chunk, $pos+1);
		return $line ;
	}

	public function get_query()
	{
		static $newline;

		$return = $newline;
		$newline = null;

		while(($line = $this->get_line()))
		{
			$line = rtrim($line,"\n");
			$cll = strlen($line);

			if (strpos($line, "started with:") === ($cll - 13))
			{
				$this->get_line(); // skip TCP Port: 3306, Named Pipe: (null)
				$this->get_line(); // skip Time                 Id Command    Argument
				$line = $this->get_line();
			}

			$matches = array();
			if(preg_match("/^(?:\d{6} {1,2}\d{1,2}:\d{2}:\d{2}|\t)\t +\d+ (\w+)/", $line, $matches))
			{
				// if log line
				$type = $matches[1];
				switch($type)
				{
					case 'Query':
						if($return)
						{
							$newline = ltrim(substr($line, strpos($line, "Query") + 5)," \t");
							break 2;
						}
						else
						{
							$return = ltrim(substr($line, strpos($line, "Query") + 5)," \t");
							break;
						}
					case 'Execute':
						if($return)
						{
							$newline = ltrim(substr($line, strpos($line, ']') + 1), " \t");
							break 2;
						}
						else
						{
							$return = ltrim(substr($line, strpos($line, ']') + 1), " \t");
							break;
						}
					default:
						if ($return)
							break 2;
						else
							break;
				}
			}
			else
			{
				$return .= $line;
			}
		}

		$r = self::normalize($return);
		return ($return === '' ? false : ($r === '' ? true : $r));
	}

	protected static function normalize($q)
	{
		$query = $q;
		$query = preg_replace("/\/\*.*\*\//sU", '', $query);				// remove multiline comments
		$query = preg_replace("/([\"'])(?:\\\\.|\\1\\1|.)*\\1/sU", "{}", $query);	// remove quoted strings
		$query = preg_replace("/(\W)(\d+)/", "\\1{}", $query);				// remove numbers
		$query = preg_replace("/\s+/", ' ', $query);					// remove multiple spaces
		$query = preg_replace("/ (\W)/","\\1", $query);					// remove spaces bordering with non-characters
		$query = preg_replace("/(\W) /","\\1", $query);					// --,--
		$query = preg_replace("/\\{\\}(,\\{\\})+/", "{}", $query);
		$query = trim(strtolower($query)," \t\n");					// trim spaces and strolower
		return $query;
	}
}

$file = isset($argv[1]) ? $argv[1] : 'c:\\atari.log' ;
if (false == ($fp = fopen($file, "rb")))
{
	die('cannot open file');
}

$ex = new extractor($fp);
$i = 0;
$j = 1;
$queries = array();
$nums = array();
$types = array();

while(($line = $ex->get_query()))
{
	$t = preg_split("/[^a-z]/", $line, 2);
	$type = $t[0];
	$hash = md5($line);

	if (!array_key_exists($type, $types))
	{
		$types[$type] = 1;
	}
	else
	{
		$types[$type]++;
	}

	if (!array_key_exists($hash, $queries))
	{
		$queries[$hash] = $line;
		$nums[$hash] = 1;
	}
	else
	{
		$nums[$hash]++;
	}
	$i++;
	//echo memory_get_usage(),"\n";
}
arsort($nums);
arsort($types);

printf("Queries by type:\n================\n");
foreach($types as $type=>$num)
{
	printf("% -20s % -10s [%5s%%] \n", $type, number_format($num, 0, '', ' '), number_format(100*$num/$i,2));
}
printf("---------------\nTotal: ".number_format($i, 0, '', ' ')." queries\n\n\n");
printf("Queries by pattern:\n===================\n");
foreach($nums as $hash => $num)
{
	printf("%d.\t% -10s [% 5s%%] - %s\n", $j++, number_format($num, 0, '', ' '), number_format(100*$num/$i,2), $queries[$hash]);
	// if($j>50) break;
}
printf("---------------\nTotal: ".number_format(--$j, 0, '', ' ')." patterns");
?>