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
	$query = preg_replace("/\\/\\*.*\\*\\//sU", '', $query);                       // remove multiline comments
	$query = preg_replace("/([\"'])(?:\\\\.|\\1\\1|.)*\\1/sU", "{}", $query);      // remove quoted strings
	$query = preg_replace("/(\\W)(?:-?\\d+(?:\\.\\d+)?)/", "\\1{}", $query);       // remove numbers
	$query = preg_replace("/(\\W)null(?:\\Wnull)*(\\W|\$)/i", "\\1{}\\2", $query); // remove nulls
	$query = preg_replace("/\\s+/", ' ', $query);                                  // remove multiple spaces
	$query = preg_replace("/ (\\W)/","\\1", $query);                               // remove spaces bordering with non-characters
	$query = preg_replace("/(\\W) /","\\1", $query);                               // --,--
	$query = preg_replace("/\\{\\}(?:,\\{\\})+/", "{}", $query);                   // repetitive {},{} to single {}
	$query = preg_replace("/\\(\\{\\}\\)(?:,\\(\\{\\}\\))+/", "({})", $query);     // repetitive ({}),({}) to single ({})
	$query = trim(strtolower($query)," \t\n");                                     // trim spaces and strolower
	return $query;
}

/**
 * Extracts normalized queries from mysql query log one by one
 *
 */
class extractor
{
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
			if(preg_match("/^(?:\\d{6} {1,2}\\d{1,2}:\\d{2}:\\d{2}|\t)\t +\\d+ (\\w+)/", $line, $matches))
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

/**
 * Output program usage doc and die
 *
 * @param string $msg - describing message
 */
function doc($msg = null)
{
	echo (!is_null($msg) ? ($msg."\n\n") : '').

		"MyProfi: mysql log profiler and analyzer\n\n",
		"Usage: ",
		"php parser.php [OPTIONS] INPUTFILE \n\n",
		"Options:\n",
		"-top N\n",
		"\tOutput only N top queries\n",
		"-type \"query types\"\n",
		"\tOuput only statistics for the queries of given query types.\n",
		"\tQuery types are comma separated words that queries may begin with\n",
		"-sample\n",
		"\tOutput one sample query per each query pattern to be able to use it\n",
		"\twith EXPLAIN query to analyze it's performance\n",
		"-csv\n",
		"\tConsideres an input file to be in csv format\n",
		"\tNote, that if the input file extension is .csv, it is also considered as csv\n\n",
		"Example:\n",
		"\tphp parser.php -csv -top 10 -type \"select, update\" general_log.csv\n"
		;
	exit;
}

if (isset($argv[1]))
	$file = array_pop($argv); // the last argument always must be an input filename
else
{
	doc('Error: no input file specified');
}

$top    = null;
$prefx  = null;
$sample = false;
$csv    = false;

array_shift($argv); // get rid of program filename ($argvs[0])

// getting command line options
while(null !== ($com = array_shift($argv)))
{
	switch ($com)
	{
		case '-top':
			if (is_null($top = array_shift($argv)))
				doc('Error: must specify the number of top queries to output');

			if (!($top = (int)$top))
				doc('Error: top number must be integer value');

			break;
		case '-type':
			if (is_null($prefx = array_shift($argv)))
				doc('Error: must specify coma separated list of query types to output');
			$prefx = explode(',', $prefx);
			$prefx = array_map('trim', $prefx);
			$prefx = array_map('strtolower', $prefx);
			$prefx = array_flip($prefx);
			break;

		case '-sample':
			$sample = true;
			break;

		case '-csv':
			$csv = true;
			break;
	}
}

if (false === ($fp = fopen($file, "rb")))
{
	doc('Error: cannot open input file '.$file);
}

if ($csv || (strcasecmp(".csv", substr($file, -4)) == 0))
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
	$t = preg_split("/[\\W]/", $line, 2);
	$type = $t[0];

	if (!is_null($prefx) && !isset($prefx[$type]))
		continue;

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

if (!is_null($top))
	$nums = array_slice($nums, 0, $top);

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
?>