#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Yandex::Tools;

Test::More::plan("tests" => 4);

sub runSub {

       my $blah = "blahblah";
       my $out= $_[0];
       my $err= $_[1];

       my $s = sub {
               print "$blah\n";
               print "$$: Hello $out\n";
               warn "Boo!\n$err\n";
       };

       print "About to fork\n";
       return Yandex::Tools::run_forked($s);
}

print "current pid: $$\n";
my $retval= runSub("sailor", "eek!");

ok($retval->{"stdout"} =~ /blahblah/, "run_forked perl sub stdout 1");
ok($retval->{"stdout"} =~ /Hello sailor/, "run_forked perl sub stdout 2");

ok($retval->{"stderr"} =~ /Boo/, "run_forked perl sub stderr 1");
ok($retval->{"stderr"} =~ /eek/, "run_forked perl sub stderr 2");

