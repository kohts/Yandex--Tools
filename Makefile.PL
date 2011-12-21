#!/usr/bin/perl
use strict;
use ExtUtils::MakeMaker;

my $prereqs = {
  'Cwd'  => 0,
  'Storable'  => 0,
  'Time::HiRes'  => 0,
  'Time::Local'  => 0,
  };

if ($^O ne 'linux') {
  $prereqs->{'Proc::ProcessTable'} => 0;
}

WriteMakefile(
  NAME          => 'Yandex::Tools',
  VERSION_FROM  => 'lib/Yandex/Tools.pm',
  ABSTRACT_FROM => 'lib/Yandex/Tools.pm',
  PREREQ_PM     => $prereqs,
  AUTHOR        => 'Petya Kohts <petya@kohts.ru>',
  );
