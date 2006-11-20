<?php

/**
 * MyProfi is mysql profiler and anlyzer, which outputs statistics of mostly
 * used queries by reading query log file.
 *
 * Copyright (C) 2006 camka at camka@users.sourceforge.net
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * @author camka
 * @package MyProfi
 */


/**
 * Normalize query: remove variable data and replace it with {}
 *
 * @param string $q
 * @return string
 */
function normalize($q)
{
	$query = $q;
	$query = preg_replace("/\\/\\*.*\\*\\//sU", '', $query);				// remove multiline comments
	$query = preg_replace("/([\"'])(?:\\\\.|\\1\\1|.)*\\1/sU", "{}", $query);	// remove quoted strings
	$query = preg_replace("/(\\W)(\\d+)/", "\\1{}", $query);				// remove numbers
	$query = preg_replace("/\\s+/", ' ', $query);					// remove multiple spaces
	$query = preg_replace("/ (\\W)/","\\1", $query);					// remove spaces bordering with non-characters
	$query = preg_replace("/(\\W) /","\\1", $query);					// --,--
	$query = preg_replace("/\\{\\}(,\\{\\})+/", "{}", $query);
	$query = trim(strtolower($query)," \t\n");					// trim spaces and strolower
	return $query;
}

/**
 * Extracts normalized queries from mysql query log one by one
 *
 */
class extractor
{
	/**
	 * Size of a chunk of file to preread into memory
	 *
	 */
	const CHUNK_SIZE = 102400; // bytes

	/**
	 * Open file pointer
	 *
	 * @var resource
	 */
	protected $fp;

	/**
	 * Initialize extractor object
	 *
	 * @param resource $fp - file pointer
	 */
	public function __construct($fp)
	{
		$this->fp = $fp;
	}

	/**
	 * Fetch the next query pattern from stream
	 *
	 * @return string
	 */
	public function get_query()
	{
		static $newline;

		$return = $newline;
		$newline = null;

		$fp = $this->fp;

		while(($line = fgets($fp)))
		{
			$line = rtrim($line,"\n");

			// skip server start log lines
			if (substr($line, -13) == "started with:")
			{
				fgets($fp); // skip TCP Port: 3306, Named Pipe: (null)
				fgets($fp); // skip Time                 Id Command    Argument
				$line = fgets($fp);
			}

			$matches = array();
			if(preg_match("/^(?:\\d{6} {1,2}\\d{1,2}:\\d{2}:\\d{2}|\t)\t +\\d+ (\w+)/", $line, $matches))
			{
				// if log line
				$type = $matches[1];
				switch($type)
				{
					case 'Query':
						if($return)
						{
							$newline = ltrim(substr($line, strpos($line, "Q") + 5)," \t");
							break 2;
						}
						else
						{
							$return = ltrim(substr($line, strpos($line, "Q") + 5)," \t");
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

		return ($return === '' || is_null($return)? false : ('' === ($r = normalize($return)) ? true : $r));
	}
}

/**
 * Read mysql query log in csv format (as of mysql 5.1 it by default)
 *
 */
class csvreader
{
	/**
	 * csv file pointer
	 *
	 * @var resource
	 */
	protected $fp = null;

	/**
	 * Initialize object
	 *
	 * @param unknown_type $fp
	 */
	public function __construct($fp)
	{
		$this->fp = $fp;
	}

	/**
	 * Fetch next query from csv file
	 *
	 * @return string - or FALSE on file end
	 */
	public function get_query()
	{
		while (false !== ($data = fgetcsv($this->fp)))
		{
			if ((!isset($data[4])) || (($data[4] !== "Query") && ($data[4] !== "Execute")) || (!$data[5]))
				continue;

			return normalize(str_replace(array("\\\\",'\\"'), array("\\",'"'), $data[5]));
		}
		return false;
	}
}
echo date("\nH:i:s\n");

if (isset($argv[1]))
	$file = $argv[1];
else
{
	echo "MyProfi: mysql log profiler and analyzer\n",
		"usage: ",
		"php parser.php INPUTFILE [>outputfile]\n\n",
		"If file extension is .csv, then file is parsed as\n ",
		"csv table file for query logging by default as of mysql 5.1\n ";
	exit;
}

if (false == ($fp = fopen($file, "rb")))
{
	die('Error: cannot open file');
}

if (strcasecmp(".csv", substr($file, -4)) == 0)
	$ex = new csvreader($fp);
else
	$ex = new extractor($fp);


$i = 0;
$j = 1;
$queries = array();
$nums = array();
$types = array();

// group queries by type and pattern
while(($line = $ex->get_query()))
{
	// extract first word to determine query type
	$t = preg_split("/[^a-z]/", $line, 2);
	$type = $t[0];
	$hash = md5($line);

	// calculate query by type
	if (!array_key_exists($type, $types))
		$types[$type] = 1;
	else
		$types[$type]++;

	// calculate query by pattern
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
}
printf("---------------\nTotal: ".number_format(--$j, 0, '', ' ')." patterns");
echo date("\nH:i:s");
?>