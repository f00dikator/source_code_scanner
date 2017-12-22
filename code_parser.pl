#!/usr/bin/perl

# try to auto-inject '; EXEC master..xp_cmdshell('shell command here')--

# John Lampe's rudimentary c0de parser...under construction 2006
$DEBUG = 0;

$file = shift;
if ( ($file =~ /code_parser.pl/) || ($file =~ /\.(db|png|jpg|jpeg|gif|dll)$/i) )
{
	if ($DEBUG == 1) {print "binary file $file.  Exiting\n";}
	exit(0);
}
else
{
	if ($DEBUG == 1) {print "Parsing $file\n";}
}

$cryptcount = 0;
$javascript = 0;
$customerror = 0;
@LOW = ();
@MEDIUM = ();
@HIGH = ();
@INFO = ();

if ($file =~ /\.config$/)
{
	$configfile = 1;
}
else
{
	$configfile = 0;
}

open (IN, "$file") || die "$!\n";

while (<IN>)
{
	if ($configfile == 1)
	{
		# <add key="HRDBReadWrite" value="Data Source=LAREDO; Initial Catalog=HR;User Id=UN1; Password=Pass1;" />
		if ($_ =~ /[pP][aA][sS][sS][wW]([oO][rR])?[dD](\s+)?=/)
		{
			$alert =  "HIGH $file --- Password stored in .config file\n$_\n\n";
			push (@HIGH,$alert);
		}
	}
	# "Select * From Customers where CustomerName = " & txtCustomerName.Value
	if ($_ =~ /.*[sS][eE][lL][eE][cC][tT].* [fF][rR][oO][mM].* [wW][hH][eE][rR][eE].* =.* \&(\s+)?[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+/)
	{
		$alert = "HIGH --- Noted a potentially dangerous SQL statement which inserts user-supplied data into the SQL query\n$_\n";
		push (@HIGH,$alert);
	}
	if ($_ =~ /<(\s+)?[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT](\s+)?>/)
	{
		$javascript = 1;
	}
	if ($_ =~ /<(\s+)?\/[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT](\s+)?>/)
	{
		$javascript = 0;
	}
	if ( ($_ =~ /<(\s+)?[cC][uU][sS][tT][oO][mM][eE][rR][rR][oO][rR][sS]/) && 
		($_ =~ /[mM][oO][dD][eE](\s+)?=(\s+)?\"[oO][fF][fF]\"/) )
	{
		$alert = "MEDIUM $file --- customErrors should be set to either 'remoteOnly' or 'On'\n$_\n";
		push (@MEDIUM,$alert);
	}
	if ($_ =~ /<(\s+)?[cC][uU][sS][tT][oO][mM][eE][rR][rR][oO][rR][sS](\s+)?>/)
	{
		$customerror = 1;
	}
	if ($_ =~ /<(\s+)?\/[cC][uU][sS][tT][oO][mM][eE][rR][rR][oO][rR][sS](\s+)?>/)
	{
		$customerror = 0;
	}
	if ( ($customerror == 1) && ($_ =~ /[mM][oO][dD][eE](\s+)?=(\s+)?\"[oO][fF][fF]\"/) )
	{
		$alert = "MEDIUM $file --- customErrors should be set to either 'remoteOnly' or 'On'\n$_\n";
		push (@MEDIUM,$alert);
        }
	if ($_ =~ /ValidateRequest(\s+)?=(\s+)?\"[fF][aA][lL][sS][eE]\"/)
	{
		$alert = "MEDIUM $file --- ValidateRequest was set to FALSE.  This means that the web application\n";
		$alert .= "has disabled dangerous input validation (such as SQL injection, XSS, and more.  Bust a freaking\n";
		$alert .= "cap in this app\n$_\n";
		push (@MEDIUM,$alert);
	}	
	if ($_ =~ /Dim .* As DataView/)
	{
		$alert = "LOW $file --- We noted a VB variable declaration to a DataView.  Ensure that data passed\n";
		$alert .= "to/from the database is thoroughly scrubbed and sanitized\n$_\n";
		push (@LOW,$alert);
	}
	if ($_ =~ /DataView .*\;/)
	{
		$alert = "LOW $file --- We noted a C# variable declaration to a DataView.  Ensure that data passed\n";
                $alert .= "to/from the database is thoroughly scrubbed and sanitized\n$_\n";
                push (@LOW,$alert);
	}
	if ( ($javascript == 1) && ($_ =~ /[eE][vV][aA][lL](\s+)?\(.*\)/) )
	{
		$alert = "MEDIUM $file --- javascript use of eval() detected\n$_\n";
		push (@MEDIUM,$alert);
	}
	if ($_ =~ /RegularExpressionValidator/)
	{
		$alert = "MEDIUM $file --- We noted a call to RegularExpressionValidator, typically used for client-side parsing\n";
		$alert .= "Ensure that similar parsing also takes place at the SERVER level.  If not, this is largely exploitable\n$_\n";
		push (@MEDIUM,$alert);
	}
	if ($_ =~ /asp:RequiredFieldValidator/)
	{
		$alert = "MEDIUM $file --- We noted a call to RequiredFieldValidator, this control is used in ASP pages to mark\n";
		$alert .= "a particular form value as required.  Many lazy programmers will just assume that the client-side scripting\n";
		$alert .= "will ensure that the data parsed at the server level is clean.  Ensure that you attempt to POST to the server\n";
		$alert .= "without this value\n$_\n";
		push (@MEDIUM,$alert);
	}
	if ($_ =~ /CompareValidator/)
	{
		$alert = "MEDIUM $file --- We noted a call to CompareValidator, this control is used in ASP pages to ensure that multiple\n";
		$alert .= "form values match (such as password boxes).   Many lazy programmers will just assume that the client-side scripting\n";
                $alert .= "will ensure that the data parsed at the server level is clean.  Ensure that you attempt to POST to the server\n";
                $alert .= "without this value\n$_\n";
                push (@MEDIUM,$alert);
	}
	if ($_ =~ /RangeValidator/)
	{
		$alert = "MEDIUM $file --- We noted a call to RangeValidator, this control is used in ASP pages to ensure valid form ranges\n";
		$alert .= "Many lazy programmers will just assume that the client-side scriptingwill ensure that the data parsed at the server\n";
		$alert .= "level is clean.  Ensure that you attempt to POST to the server invalid ranges\n$_\n";
		push (@MEDIUM,$alert);
	}
	if ($_ =~ /CustomValidator/)
	{
		$alert = "MEDIUM $file --- We noted a call to CustomValidator, this control is used in ASP pages to ensure valid form values\n";
		$alert .= "Many lazy programmers will just assume that the client-side scriptingwill ensure that the data parsed at the server\n";
                $alert .= "level is clean.  Ensure that you attempt to POST to the server invalid ranges\n$_\n";
		push (@MEDIUM,$alert);
	}
	if ($_ =~ /[tT][rR][aA][cC][eE](\s+)?=(\s+)?\"[Tt][rR][uU][eE]\"/)
	{
		$alert = "MEDIUM $file --- 'TRACE=True' Found\n$_\n";
		push (@MEDIUM,$alert);
	}
        if ($_ =~ /[dD][eE][bB][uU][gG](\s+)?=(\s+)?\"[Tt][rR][uU][eE]\"/)
        {
                # <%@ Page language="c#" Trace="false" Debug="true" %>
		$alert = "MEDIUM $file --- 'DEBUG=True' Found\n$_\n";
		push (@MEDIUM,$alert);
        }
	if ($_ =~ /.*[iI][nN][nN][eE][rR][hH][tT][mM][lL]\..*/)
	{
		$alert = "MEDIUM $file --- Inner.HTML statement found\n$_\n";
		push (@MEDIUM,$alert);
	}
	if ($_ =~ /<[mM][eE][tT][aA] .*\"[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]\"/)
	{
		if ($_ !~ /[cC][hH][aA][rR][sS][eE][tT]/)
		{
			$alert = "MEDIUM $file --- Content-Type META tag found without a charset declaration\n$_\n";
			push (@MEDIUM,$alert);
		}
	}
	if ($_ =~ /.*(Rnd|Random).*/)
	{
		$alert = "MEDIUM $file --- Use of Rnd() or Random() which is random but predictable\n$_\n";
		push (@MEDIUM,$alert);
	}
	if ($_ =~ /CryptAcquireContext/)
	{
		$cryptcount++;
	}
	if ($_ =~ /strcpy/)
	{
		$alert = "MEDIUM $file --- Use of strcpy().  Very bad\n$_\n";
		push (@MEDIUM,$alert);
	}
	if ($_ =~ /Response\.Write(\s+)?\(Request\./)
	{
		$alert = "MEDIUM $file --- Response.Write(Request.*) Detected.  Possible injection flaw\n$_\n";
		push (@MEDIUM,$alert);
        }
	if ($_ =~ /a href(\s+)?=(\s+)?<\%=.*\%>/)
	{
		$alert = "MEDIUM $file --- Use of user-supplied data with an automated call to 'a href'\n$_\n";
		push (@MEDIUM,$alert);
        }
	if ($_ =~ /LCMapString/)
	{
		$alert = "MEDIUM $file --- Use of LCMapString().  Microsoft _Writing Secure Code_ warns of deprecation of this function\n$_\n";
		push (@MEDIUM,$alert);
        }
	if ($_ =~ /InitSockAddr|WSAAccept/)
	{
		$alert = "MEDIUM $file --- Use of InitSockAddr() which attempts to bind() a socket.  See why the app is opening a listener\n$_\n";
		push (@MEDIUM,$alert);
        }
	if ($_ =~ /document\.write(\s+)?\(location\./)
	{
		$alert = "MEDIUM $file --- Use of user-supplied data with an automated call to document.write()\n$_\n";
		push (@MEDIUM,$alert);
        }
	if ($_ =~ /MarshalByRefObject/)
	{
		$alert = "MEDIUM $file --- MarshalByRefObject() called.  This indicates a remotable object being created\n$_\n";
		push (@MEDIUM,$alert);
        }
	if ($_ =~ /Regex|System\.Text\.RegularExpressions|\.Pattern|RegExp|RegExPattern|RegularExpression/)
	{
		$alert = "LOW $file --- Evaluate the following regex() for validity and ensure that UNICODE cannot be passed to this regex\n$_\n";
		push (@LOW,$alert);
	}
	if ($_ =~ /Regex\.Replace/)
	{
	  $alert = "MEDIUM $file --- The use of Regex.Replace() should be replaced with a regex which defines what is allowed...not what is disallowed\n$_\n";
	  push (@MEDIUM,$alert);
	}
	if ($_ =~ /GetServerVariable/)
	{
		$alert = "LOW $file --- Noted a call to GetServerVariable().  Manually inspect for flaw\n$_\n";
		push (@LOW,$alert);
        }
	if ($_ =~ /MultiByteToWideChar/)
	{
		$alert = "LOW $file --- Manually inspect the arguments passed to MultiByteToWideChar().  This function has been problematic\n$_\n";
		push (@LOW,$alert);
	}
	if ($_ =~ /SqlConnection/i)
	{
		$alert = "LOW $file --- Manually inspect the arguments passed to the object created by SqlConnection\n$_\n";
		push (@LOW,$alert);
        }
	if ($_ =~ /SqlDataAdapter/)
	{
		$alert = "LOW $file --- Manually inspect the arguments passed to the object created by SqlDataAdapter\n$_\n";
                push (@LOW,$alert);
	}
        if ($_ =~ /Provider(\s+)?=(\s+)?sqloledb/)
        {
		$alert = "LOW $file --- Manually inspect the arguments passed to the object created by sqloledb\n$_\n";
		push (@LOW,$alert);
        }
        if ($_ =~ /System\.Data\.SqlClient/)
        {
		$alert = "LOW $file --- Manually inspect the arguments passed to the object created by System.Data.SqlClient\n$_\n";
		push (@LOW,$alert);
        }
	if ($_ =~ /<\%\@\s*Page[^\%]*\%>/)
	{
		$alert = "INFO $file --- The file is not compliant with .NET 2 best practices\n$_\n";
		push (@INFO, $alert);
	}

}

if ($cryptcount > 0)
{
	$alert = "MEDIUM $file --- CryptAcquireContext() was called $cryptcount times.  This is a severe hit to performance\n";
	push (@MEDIUM,$alert);
}



# REPORTING
if ($#HIGH >= 0)
{
	print "-" x 80;
	print "\n";
	foreach $h (@HIGH)
	{
		print "$h";
	}
}


if ($#MEDIUM >= 0)
{
	print "-" x 80;
	print "\n";
	foreach $h (@MEDIUM)
	{
        	print "$h";
	}
}

if ($#LOW >= 0)
{
	print "-" x 80;
	print "\n";
	foreach $h (@LOW)
	{
        	print "$h";
	}
}


if ($#INFO >= 0)
{
	print "-" x 80;
	print "\n";
	foreach $h (@INFO)
	{
        	print "$h";
	}
}




exit(0);







