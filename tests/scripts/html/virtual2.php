<?php 
	echo 'Virtual 2'.PHP_EOL;
	echo 'Starting sub 2a'.PHP_EOL;
	virtual('/virtual2a.php');
	echo 'Ended sub2a'.PHP_EOL;
	echo 'Embedding html'.PHP_EOL;
	virtual('/index.html');
	echo 'Done embedding html'.PHP_EOL;
?>
