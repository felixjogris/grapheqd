#!/usr/bin/perl -w

use strict;
use warnings;

my ($file_name, $content_type, $var_name) = @ARGV;
if (!$file_name || !$content_type || !$var_name) {
  die "usage: bin2c.pl <local file name> <http content type> " .
      "<c variable name>";
}

open(my $fh, "<", $file_name) || die "$file_name: $!";
binmode($fh) || die "$file_name: binmode(): $!";
my $data;
{
  local $/;
  $data = <$fh>;
}
close($fh);

my $content_len = length($data);

$data = "Content-Type: $content_type\r\n" .
        "Content-Length: $content_len\r\n" .
        "\r\n" .
        $data;

my $hfile = "$var_name.h";
open($fh, ">", $hfile) || die "$hfile: $!";
binmode($fh) || die "$hfile: binmode(): $!";

print $fh "char $var_name\[\] = { ";
while ($data =~ s/^(.)//ms) {
  my $char = $1;
  print $fh sprintf("0x%02hx", ord($char));
  if ($data ne "") {
    print $fh ",";
    print $fh "\n" if ($char eq "\n");
  }
}
print $fh " };\n";

close($fh);
