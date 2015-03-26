<?php
	echo "SUMMARY".PHP_EOL;
	echo "REQUEST HEADERS:".PHP_EOL;
	print_r(apache_request_headers());
	echo "RESPONSE HEADERS:".PHP_EOL;
	print_r(apache_response_headers());
	echo "FILES GLOBAL:".PHP_EOL;
	print_r($_FILES);
	echo "SERVER GLOBAL:".PHP_EOL;
	print_r($_SERVER);
	echo "POST GLOBAL:".PHP_EOL;
	print_r($_POST);
	echo "GET GLOBAL:".PHP_EOL;
	print_r($_GET);
	$postdata = file_get_contents('php://input');
	echo "Length of raw post:" . strlen($postdata).PHP_EOL;
?>
