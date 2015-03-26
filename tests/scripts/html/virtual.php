<?php 
	echo "This is virtual top. Starting 2.".PHP_EOL;
?>
<?php
	virtual('/virtual2.php');
?>
<?php
	echo "Behind virtual 2.".PHP_EOL;
	echo "Starting virtual 3.".PHP_EOL;
	virtual('/virtual3.php');
	echo "Ended  virtual 3.".PHP_EOL;
?>
