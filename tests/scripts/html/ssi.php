<?php
	echo 'Going virtual.'.PHP_EOL;
	virtual('/summary.php?id=ssi-summary');
	echo 'Backtrace?'.PHP_EOL;
	print_r(debug_backtrace()); 
?>
