#!/usr/bin/perl -w

use strict;
use warnings;

foreach my $channel(qw(left right)) {
  for (my $band = 0; $band < 27; $band++) {
    print "<div class=\"band\">\n";
    for (my $bar = 24; $bar >= 0; $bar--) {
      print "<div id=\"$channel$band\_$bar\" class=\"bar\"></div>\n";
    }
    print "<div id=\"$channel$band"."hz\" class=\"hz\"></div>\n";
    print "</div>"; # no newline to prevent space between inline-blocks
  }
}
