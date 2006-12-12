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
	$query = str_replace (array("\\n", "\\t", "\\0"), ' ', $query);                // replace escaped linebreaks
	$query = preg_replace("/\\s+/", ' ', $query);                                  // remove multiple spaces
	$query = preg_replace("/ (\\W)/","\\1", $query);                               // remove spaces bordering with non-characters
	$query = preg_replace("/(\\W) /","\\1", $query);                               // --,--
	$query = preg_replace("/\\{\\}(?:,\\{\\})+/", "{}", $query);                   // repetitive {},{} to single {}
	$query = preg_replace("/\\(\\{\\}\\)(?:,\\(\\{\\}\\))+/", "({})", $query);     // repetitive ({}),({}) to single ({})
	$query = strtolower(trim($query," \t\n)("));                                     // trim spaces and strolower
	return $query;
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

/**
 * Interface for all query fetchers
 *
 */
interface query_fetcher
{
	/**
	 * Get next query in the flow
	 *
	 */
	public function get_query();
}

/**
 * Generral filereader class
 *
 */
abstract class filereader
{
	/**
	 * File pointer
	 *
	 * @var resource
	 */
	public $fp;

	/**
	 * Attempts to open a file
	 * Dies on failure
	 *
	 * @param string $filename
	 */
	public function __construct($filename)
	{
		if (false === ($this->fp = fopen($filename, "rb")))
		{
			doc('Error: cannot open input file '.$filename);
		}
	}

	/**
	 * Close file on exit
	 *
	 */
	public function __destruct()
	{
		fclose($this->fp);
	}
}

/**
 * Extracts normalized queries from mysql query log one by one
 *
 */
class extractor extends filereader implements query_fetcher
{
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
			$line = rtrim($line,"\r\n");

			// skip server start log lines
			if (substr($line, -13) == "started with:")
			{
				fgets($fp); // skip TCP Port: 3306, Named Pipe: (null)
				fgets($fp); // skip Time                 Id Command    Argument
				continue;
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

		return ($return === '' || is_null($return)? false : $return);
	}
}

/**
 * Read mysql query log in csv format (as of mysql 5.1 it by default)
 *
 */
class csvreader extends filereader implements query_fetcher
{
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

			// cut statement id from prefix of prepared statement
			$d5 = $data[5];
			$query = ('Execute' == $data[4] ? substr($d5, strpos($d5,']')+1) : $d5 );

			return str_replace(array("\\\\",'\\"'), array("\\",'"'), $query);
		}
		return false;
	}
}

/**
 * Main statistics gathering class
 *
 */
class myprofi
{
	/**
	 * Query fetcher class
	 *
	 * @var mixed
	 */
	protected $fetcher;

	/**
	 * Top number of queries to output in stats
	 *
	 * @var integer
	 */
	protected $top = null;

	/**
	 * Only queries of these types to calculate
	 *
	 * @var array
	 */
	protected $types = null;

	/**
	 * Will the input file be processed as CSV formatted
	 *
	 * @var boolean
	 */
	protected $csv = false;

	/**
	 * Will the statistics include a sample query for each
	 * pattern
	 *
	 * @var boolean
	 */
	protected $sample = false;

	/**
	 * Input filename
	 */
	protected $filename;

	protected $_queries = array();
	protected $_nums    = array();
	protected $_types   = array();
	protected $total    = 0;

	/**
	 * Set the object that can fetch queries one by one from
	 * some storage
	 *
	 * @param query_fetcher $prov
	 */
	protected function set_data_provider(query_fetcher $prov)
	{
		$this->fetcher = $prov;
	}

	/**
	 * Set maximum number of queries
	 *
	 * @param integer $top
	 */
	public function top($top)
	{
		$this->top = $top;
	}

	/**
	 * Set array of query types to calculate
	 *
	 * @param string $types - comma separated list of types
	 */
	public function types($types)
	{
		$types = explode(',', $types);
		$types = array_map('trim', $types);
		$types = array_map('strtolower', $types);
		$types = array_flip($types);

		$this->types = $types;
	}

	/**
	 * Set the csv format of an input file
	 *
	 * @param boolean $csv
	 */
	public function csv($csv)
	{
		$this->csv = $csv;
	}

	/**
	 * Keep one sample query for each pattern
	 *
	 * @param boolean $sample
	 */
	public function sample($sample)
	{
		$this->sample = $sample;
	}

	/**
	 * Set input file
	 *
	 * @param string $filename
	 */
	public function set_input_file($filename)
	{
		if (!$this->csv && (strcasecmp(".csv", substr($filename, -4)) === 0))
			$this->csv(true);

		$this->filename = $filename;
	}

	/**
	 * The main routine so count statistics
	 *
	 */
	public function process_queries()
	{
		if ($this->csv)
			$this->set_data_provider(new csvreader($this->filename));
		else
			$this->set_data_provider(new extractor($this->filename));

		// counters
		$i = 0;

		// stats arrays
		$queries = array();
		$nums    = array();
		$types   = array();
		$samples = array();

		// temporary assigned properties
		$prefx   = $this->types;
		$ex      = $this->fetcher;

		// group queries by type and pattern
		while(($line = $ex->get_query()))
		{
			if ('' == ($line = normalize($line))) continue;

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

		if (!is_null($this->top))
			$nums = array_slice($nums, 0, $this->top);

		$this->_queries = $queries;
		$this->_nums    = $nums;
		$this->_types   = $types;

		$this->total    = $i;
	}

	public function get_types_stat()
	{
		return new ArrayIterator($this->_types);
	}

	public function get_pattern_stats()
	{
		if (list($h,$n) = each ($this->_nums))
		{
			return array($n, $this->_queries[$h]);
		}
		else
			return false;
	}

	public function total()
	{
		return $this->total;
	}
}

 // the last argument always must be an input filename
if (isset($argv[1]))
	$file = array_pop($argv);
else
{
	doc('Error: no input file specified');
}

// get rid of program filename ($argvs[0])
array_shift($argv);

// initialize an object
$myprofi = new myprofi();

// iterating through command line options
while(null !== ($com = array_shift($argv)))
{
	switch ($com)
	{
		case '-top':
			if (is_null($top = array_shift($argv)))
				doc('Error: must specify the number of top queries to output');

			if (!($top = (int)$top))
				doc('Error: top number must be integer value');
				$myprofi->top($top);
			break;
		case '-type':
			if (is_null($prefx = array_shift($argv)))
				doc('Error: must specify coma separated list of query types to output');
				$myprofi->types($prefx);
			break;

		case '-sample':
			$myprofi->sample(true);
			break;

		case '-csv':
			$myprofi->csv(true);
			break;
	}
}

$myprofi->set_input_file($file);
$myprofi->process_queries();

$i = $myprofi->total();
$j = 1;
printf("Queries by type:\n================\n");
foreach($myprofi->get_types_stat() as $type => $num)
{
	printf("% -20s % -10s [%5s%%] \n", $type, number_format($num, 0, '', ' '), number_format(100*$num/$i,2));
}
printf("---------------\nTotal: ".number_format($i, 0, '', ' ')." queries\n\n\n");
printf("Queries by pattern:\n===================\n");
while(list($num, $query) = $myprofi->get_pattern_stats())
{
	printf("%d.\t% -10s [% 5s%%] - %s\n", $j++, number_format($num, 0, '', ' '), number_format(100*$num/$i,2), $query);
}
printf("---------------\nTotal: ".number_format(--$j, 0, '', ' ')." patterns");
?>