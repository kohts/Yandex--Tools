package Yandex::Tools;

use 5.008;
use strict;
use warnings;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

require Exporter;

$VERSION = '0.15';
@ISA = qw(Exporter);
@EXPORT_OK = qw (
  can_log
  do_log
  get_log_filename
  get_log_options
  set_log_filename
  set_log_options

  can_write
  fileinfo_struct
  read_dir
  read_file_array
  read_file_option
  read_file_scalar
  write_file_option
  write_file_scalar

  array_clear_dupes
  canonize_delimiters
  is_ascii
  is_digital
  safe_string

  matches_with_one_of_regexps

  get_callstack

  daemonize
  run_forked
  
  send_mail
);

use POSIX;
use utf8;
use Data::Dumper;
use File::Path;
use IPC::Open3;
use IO::Select;
use IO::Handle; # autoflush
use FileHandle;
use Time::HiRes qw/usleep clock_gettime CLOCK_MONOTONIC/;
use Socket; # socketpair
use File::Basename; # basename
use File::Path; # mkpath
use File::Copy;
use Carp;
use Storable;

my $have_mime_lite;
eval {
  require MIME::Lite;
  MIME::Lite->import();
  require MIME::Base64;
  MIME::Base64->import();
  require MIME::QuotedPrint;
  MIME::QuotedPrint->import();
  require File::MMagic;
  File::MMagic->import();
};
$have_mime_lite = 1 unless $@;

# variables available for programs importing this library,
# should be removed (!)
our $debug;
our $debug2;
our $cmd;
our $cmd_opts;
our $new_cmd_opts;
our $command = "";

our $HOOKS = {};

# read file, removing carriage returns
sub read_file_option {
  my ($filename, $opts) = @_;
  $opts = {} unless $opts;

  my $t = undef;
  
  if (-e $filename || $opts->{'mandatory'}) {
    $t = read_file_scalar($filename);
    $t =~ s/[\r\n]//sgo;
  }

  return $t;
}

sub write_file_option {
  my ($filename, $value, $opts) = @_;

  $opts = {} unless $opts;
  my $fh = Yandex::Tools::safe_open($filename, "overwrite", {'timeout' => $opts->{'timeout'} || 2});
  return 0 unless $fh;

  $value = "" unless defined($value);

  print $fh $value . "\n";
  Yandex::Tools::safe_close($fh);
}

sub write_file_option_safe {
  my ($filename, $value, $opts) = @_;

  $opts = {} unless $opts;
  
  my $dirname = $filename;
  $dirname =~ s/\/[^\/]*$//goi;

  my $filename_tmp = $filename;
  $filename_tmp =~ s/.+\///goi;

  $filename_tmp = $dirname . "/.safe." . $filename_tmp;

  my $fh = Yandex::Tools::safe_open($filename_tmp, "overwrite", {'timeout' => $opts->{'timeout'} || 2});
  return 0 unless $fh;

  $value = "" unless defined($value);

  print $fh $value . "\n";
  Yandex::Tools::safe_close($fh);

  my $res = rename ($filename_tmp, $filename);
  return $res;
}

sub write_file_scalar {
  my ($filename, $value, $opts) = @_;

  $opts = {} unless $opts;
  my $fh = Yandex::Tools::safe_open($filename, "overwrite", {'timeout' => $opts->{'timeout'} || 2});
  return 0 unless $fh;

  $value = "" unless defined($value);

  print $fh $value;
  Yandex::Tools::safe_close($fh);
}

sub read_file_scalar {
  my ($filename) = @_;

  my $filecontent;
  unless (open F, $filename) {
    Yandex::Tools::die("Couldn't open $filename for reading: $!");
  }
  { local $/ = undef; $filecontent = <F>; }
  close F;

  return $filecontent;
}

# read file, each line is an array element
#
sub read_file_array {
  my ($filename, $opts) = @_;
  $opts = {} unless $opts;

  my $arr = [];
  my $t = undef;
  
  if (-e $filename || $opts->{'mandatory'}) {
    $t = read_file_scalar($filename);
    @{$arr} = split(/\n/so, $t);
  }

  return $arr;
}

# generate fileinfo structure
#
sub fileinfo_struct {
  my ($opts) = @_;

  $opts = {} unless $opts;

  Yandex::Tools::die("fileinfo_struct: absolute_name must be specified")
    unless $opts->{'absolute_name'};

  my $entry = {};

  # return empty struct if file does not exist
  if (! -e $opts->{'absolute_name'} && ! -l $opts->{'absolute_name'}) {
    return $entry;
  }

  foreach my $k(qw/absolute_name relative_name short_name/) {
    $entry->{$k} = $opts->{$k} if defined($opts->{$k});
  }

  if (! $entry->{'relative_name'}) {
    $entry->{'relative_name'} = $entry->{'absolute_name'};
    $entry->{'relative_name'} =~ s/^\///o;
  }
  if (! $entry->{'short_name'}) {
    $entry->{'short_name'} = File::Basename::basename($entry->{'absolute_name'});
  }

  if (-l $entry->{'absolute_name'}) {
    $entry->{'type'} = "symlink";
    $entry->{'symlink_target'} = readlink($entry->{'absolute_name'});

    # calculate absolute path for relative symlinks
    #
    if ($entry->{'symlink_target'} !~ /^\//o) {

      my $abs_dir = dirname($entry->{'absolute_name'});
      $abs_dir = $abs_dir . ($abs_dir eq "/" ? "" : "/") . $entry->{'symlink_target'};

      $entry->{'symlink_target_abs'} = $abs_dir;
    }
    else {
      $entry->{'symlink_target_abs'} = $entry->{'symlink_target'};
    }
  }
  elsif (-d $entry->{'absolute_name'}) {
    $entry->{'type'} = "dir";
  }
  else {
    $entry->{'type'} = "file";
  }

  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
    $atime,$mtime,$ctime,$blksize,$blocks) = lstat($entry->{'absolute_name'});

  # extract MASK as specified in http://perldoc.perl.org/functions/stat.html
  $mode = $mode & 07777;
  
  # saving entry attributes
  $entry->{'mode'} = $mode;
  $entry->{'uid'} = $uid;
  $entry->{'gid'} = $gid;
#  $entry->{'atime'} = $atime;
  $entry->{'mtime'} = $mtime;
  $entry->{'size'} = $size;
#      $entry->{'mode_printable'} = sprintf("%3o", $mode);

  return $entry;
}

sub read_dir {
  my ($dirname, $opts) = @_;

  $opts = {} unless $opts;
  $opts->{'output_type'} = 'arrayref'
    unless $opts->{'output_type'};

  my $dummy;
  if (!opendir($dummy, $dirname)) {
    if ($opts->{'non_fatal'}) {
      return 0;
    }
    else {
      Yandex::Tools::die("ERROR: unable to open directory [$dirname]");
    }
  }

  my @all_entries = readdir($dummy);
  close($dummy);

  my $entries;
  if ($opts->{'output_type'} eq 'arrayref') {
    $entries = [];
  }
  elsif ($opts->{'output_type'} eq 'hashref') {
    $entries = {};
  }

  foreach my $e (sort @all_entries) {
    next if $e eq '.' || $e eq '..';

    my $absolute_name = $dirname . "/" . $e;

    if ($opts->{'output_type'} eq 'arrayref') {
      # skipping non-directories if requested
      # effectively means "get only files";
      if ($opts->{'only-directories'}) {
        next if -l $absolute_name || ! -d $absolute_name;
      }
      
      # symlinks are also files
      if ($opts->{'only-files'}) {
        next if -d $absolute_name && ! -l $absolute_name;
      }

      # simple output, feasible only
      # for non-recursive directory reads
      push(@{$entries}, $e);
    }
    elsif ($opts->{'output_type'} eq 'hashref') {
      # used to generate following type of struct
      #
      # "etc" => {
      #   "short_name" => "etc",
      #   "relative_name" => "etc",
      #   "type" => "dir",
      #   }
      # "etc/passwd" => {
      #   "short_name" => "passwd",
      #   "relative_name" => "etc/passwd",
      #   "type" => "file",
      #   }

      my $relative_entry_name = "";

      # append entry relative path (if we're recursing)
      if (defined($opts->{'recursed_dir'})) {
        $relative_entry_name = $opts->{'recursed_dir'} . "/";
      }

      # append entry short name
      $relative_entry_name .= $e;

      # populate entry struct
      my $entry = Yandex::Tools::fileinfo_struct({
        'absolute_name' => $absolute_name,
        'relative_name' => $relative_entry_name,
        'short_name' => $e,
        'user_map' => $opts->{'user_map'},
        'group_map' => $opts->{'group_map'},
        });

      # append entry
      $entries->{$relative_entry_name} = $entry;

      # do recursion into directories
      # (but not into symlinked directories!)
      if (-d $absolute_name && ! -l $absolute_name) {
        my $opts_r = Storable::dclone($opts);
        $opts_r->{'recursed_dir'} = $relative_entry_name;

        my $e = read_dir($absolute_name, $opts_r);
        foreach my $ee (keys %{$e}) {
          $entries->{$ee} = $e->{$ee};
        }
      }
    }
  }

  return $entries;
}

sub disable_all_signals {
  foreach my $s (keys %SIG) {
    $SIG{$s} = 'IGNORE';
  }
}

# incompatible with POSIX::SigAction
#
sub install_layered_signal {
  my ($s, $handler_code) = @_;

  my %available_signals = map {$_ => 1} keys %SIG;

  Yandex::Tools::die("install_layered_signal got nonexistent signal name [$s]")
    unless defined($available_signals{$s});
  Yandex::Tools::die("install_layered_signal expects coderef")
    if !ref($handler_code) || ref($handler_code) ne 'CODE';

  my $previous_handler = $SIG{$s};

  my $sig_handler = sub {
    my ($called_sig_name, @sig_param) = @_;
    
    # $s is a closure referring to real signal name
    # for which this handler is being installed.
    # it is used to distinguish between
    # real signal handlers and aliased signal handlers
    my $signal_name = $s;

    # $called_sig_name is a signal name which
    # was passed to this signal handler;
    # it doesn't equal $signal_name in case
    # some signal handlers in %SIG point
    # to other signal handler (CHLD and CLD,
    # ABRT and IOT)
    #
    # initial signal handler for aliased signal
    # calls some other signal handler which
    # should not execute the same handler_code again
    if ($called_sig_name eq $signal_name) {
      $handler_code->($signal_name);
    }

    # run original signal handler if any (including aliased)
    #
    if (ref($previous_handler)) {
      $previous_handler->($called_sig_name, @sig_param);
    }
  };

  $SIG{$s} = $sig_handler;
}

# give process a chance sending TERM,
# waiting for a while (2 seconds)
# and killing it with KILL
sub kill_gently {
  my ($pid, $opts) = @_;
  
  $opts = {} unless $opts;
  $opts->{'wait_time'} = 2 unless defined($opts->{'wait_time'});
  $opts->{'first_kill_type'} = 'just_process' unless $opts->{'first_kill_type'};
  $opts->{'final_kill_type'} = 'just_process' unless $opts->{'final_kill_type'};

  if ($opts->{'first_kill_type'} eq 'just_process') {
    kill(15, $pid);
  }
  elsif ($opts->{'first_kill_type'} eq 'process_group') {
    kill(-15, $pid);
  }
  
  my $child_finished = 0;
  my $wait_start_time = clock_gettime(CLOCK_MONOTONIC);

  while (!$child_finished && $wait_start_time + $opts->{'wait_time'} > clock_gettime(CLOCK_MONOTONIC)) {
    my $waitpid = waitpid($pid, WNOHANG);
    if ($waitpid eq -1) {
      $child_finished = 1;
    }
    Time::HiRes::usleep(250000); # quarter of a second
  }

  if (!$child_finished) {
    if ($opts->{'final_kill_type'} eq 'just_process') {
      kill(9, $pid);
    }
    elsif ($opts->{'final_kill_type'} eq 'process_group') {
      kill(-9, $pid);
    }
  }
}

sub open3_run {
  my ($cmd, $opts) = @_;

  $opts = {} unless $opts;
  
  my $child_in = FileHandle->new;
  my $child_out = FileHandle->new;
  my $child_err = FileHandle->new;
  $child_out->autoflush(1);
  $child_err->autoflush(1);

  my $pid = open3($child_in, $child_out, $child_err, $cmd);

  # push my child's pid to our parent
  # so in case i am killed parent
  # could stop my child (search for
  # child_child_pid in parent code)
  if ($opts->{'parent_info'}) {
    my $ps = $opts->{'parent_info'};
    print $ps "spawned $pid\n";
  }

  if ($child_in && $child_out->opened && $opts->{'child_stdin'}) {

    # If the child process dies for any reason,
    # the next write to CHLD_IN is likely to generate
    # a SIGPIPE in the parent, which is fatal by default.
    # So you may wish to handle this signal.
    #
    # from http://perldoc.perl.org/IPC/Open3.html,
    # absolutely needed to catch piped commands errors.
    #
    local $SIG{'PIPE'} = sub { 1; };
    
    print $child_in $opts->{'child_stdin'};
  }
  close($child_in);

  my $child_output = {
    'out' => $child_out->fileno,
    'err' => $child_err->fileno,
    $child_out->fileno => {
      'parent_socket' => $opts->{'parent_stdout'},
      'scalar_buffer' => "",
      'child_handle' => $child_out,
      'block_size' => ($child_out->stat)[11] || 1024,
      },
    $child_err->fileno => {
      'parent_socket' => $opts->{'parent_stderr'},
      'scalar_buffer' => "",
      'child_handle' => $child_err,
      'block_size' => ($child_err->stat)[11] || 1024,
      },
    };

  my $select = IO::Select->new();
  $select->add($child_out, $child_err);

  # pass any signal to the child
  # effectively creating process
  # strongly attached to the child:
  # it will terminate only after child
  # has terminated (except for SIGKILL,
  # which is specially handled)
  foreach my $s (keys %SIG) {
    my $sig_handler;
    $sig_handler = sub {
      kill("$s", $pid);
      $SIG{$s} = $sig_handler;
    };
    $SIG{$s} = $sig_handler;
  }

  my $child_finished = 0;

  my $got_sig_child = 0;
  $SIG{'CHLD'} = sub { $got_sig_child = clock_gettime(CLOCK_MONOTONIC); };

  while(!$child_finished && ($child_out->opened || $child_err->opened)) {

    # parent was killed otherwise we would have got
    # the same signal as parent and process it same way
    if (getppid() eq "1") {
      
      # end my process group with all the children
      # (i am the process group leader, so my pid
      # equals to the process group id)
      #
      # same thing which is done
      # with $opts->{'clean_up_children'}
      # in run_forked
      #
      kill(-9, $$);

      exit 1;
    }

    if ($got_sig_child) {
      if (clock_gettime(CLOCK_MONOTONIC) - $got_sig_child > 1) {
        # select->can_read doesn't return 0 after SIG_CHLD
        #
        # "On POSIX-compliant platforms, SIGCHLD is the signal
        # sent to a process when a child process terminates."
        # http://en.wikipedia.org/wiki/SIGCHLD
        #
        # nevertheless kill KILL wouldn't break anything here
        #
        kill (9, $pid);
        $child_finished = 1;
      }
    }

    Time::HiRes::usleep(1);

    foreach my $fd ($select->can_read(1/100)) {
      my $str = $child_output->{$fd->fileno};
      Yandex::Tools::die("child stream not found: $fd") unless $str;

      my $data;
      my $count = $fd->sysread($data, $str->{'block_size'});

      if ($count) {
        if ($str->{'parent_socket'}) {
          my $ph = $str->{'parent_socket'};
          print $ph $data;
        }
        else {
          $str->{'scalar_buffer'} .= $data;
        }
      }
      elsif ($count eq 0) {
        $select->remove($fd);
        $fd->close();
      }
      else {
        Yandex::Tools::die("error during sysread: " . $!);
      }
    }
  }

  my $waitpid_ret = waitpid($pid, 0);
  my $real_exit = $?;
  my $exit_value  = $real_exit >> 8;

  # since we've successfully reaped the child,
  # let our parent know about this.
  #
  if ($opts->{'parent_info'}) {
    my $ps = $opts->{'parent_info'};

    # child was killed, inform parent
    if ($real_exit & 127) {
      print $ps "$pid killed with " . ($real_exit & 127) . "\n";
      
    }

    print $ps "reaped $pid\n";
  }

  if ($opts->{'parent_stdout'} || $opts->{'parent_stderr'}) {
    return $exit_value;
  }
  else {
    return {
      'stdout' => $child_output->{$child_output->{'out'}}->{'scalar_buffer'},
      'stderr' => $child_output->{$child_output->{'err'}}->{'scalar_buffer'},
      'exit_code' => $exit_value,
      };
  }
}

sub run_forked {
  my ($cmd, $opts) = @_;

  $opts = {} unless $opts;
  $opts->{'timeout'} = 0 unless $opts->{'timeout'};
  $opts->{'terminate_wait_time'} = 2 unless defined($opts->{'terminate_wait_time'});

  # turned on by default
  $opts->{'clean_up_children'} = 1 unless defined($opts->{'clean_up_children'});

  # sockets to pass child stdout to parent
  my $child_stdout_socket;
  my $parent_stdout_socket;

  # sockets to pass child stderr to parent
  my $child_stderr_socket;
  my $parent_stderr_socket;
  
  # sockets for child -> parent internal communication
  my $child_info_socket;
  my $parent_info_socket;

  socketpair($child_stdout_socket, $parent_stdout_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC) ||
    Yandex::Tools::die ("socketpair: $!");
  socketpair($child_stderr_socket, $parent_stderr_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC) ||
    Yandex::Tools::die ("socketpair: $!");
  socketpair($child_info_socket, $parent_info_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC) ||
    Yandex::Tools::die ("socketpair: $!");

  $child_stdout_socket->autoflush(1);
  $parent_stdout_socket->autoflush(1);
  $child_stderr_socket->autoflush(1);
  $parent_stderr_socket->autoflush(1);
  $child_info_socket->autoflush(1);
  $parent_info_socket->autoflush(1);

  my $start_time = clock_gettime(CLOCK_MONOTONIC);

  my $pid;
  if ($pid = fork) {

    # we are a parent
    close($parent_stdout_socket);
    close($parent_stderr_socket);
    close($parent_info_socket);

    my $flags;

    # prepare sockets to read from child

    $flags = 0;
    fcntl($child_stdout_socket, F_GETFL, $flags) || Yandex::Tools::die("can't fnctl F_GETFL: $!");
    $flags |= O_NONBLOCK;
    fcntl($child_stdout_socket, F_SETFL, $flags) || Yandex::Tools::die("can't fnctl F_SETFL: $!");

    $flags = 0;
    fcntl($child_stderr_socket, F_GETFL, $flags) || Yandex::Tools::die("can't fnctl F_GETFL: $!");
    $flags |= O_NONBLOCK;
    fcntl($child_stderr_socket, F_SETFL, $flags) || Yandex::Tools::die("can't fnctl F_SETFL: $!");

    $flags = 0;
    fcntl($child_info_socket, F_GETFL, $flags) || Yandex::Tools::die("can't fnctl F_GETFL: $!");
    $flags |= O_NONBLOCK;
    fcntl($child_info_socket, F_SETFL, $flags) || Yandex::Tools::die("can't fnctl F_SETFL: $!");

#    print "child $pid started\n";

    my $child_timedout = 0;
    my $child_finished = 0;
    my $child_stdout = '';
    my $child_stderr = '';
    my $child_merged = '';
    my $child_exit_code = 0;
    my $child_killed_by_signal = 0;
    my $parent_died = 0;

    my $got_sig_child = 0;
    my $got_sig_quit = 0;
    my $orig_sig_child = $SIG{'CHLD'};

    $SIG{'CHLD'} = sub { $got_sig_child = clock_gettime(CLOCK_MONOTONIC); };
    
    if ($opts->{'terminate_on_signal'}) {
      install_layered_signal($opts->{'terminate_on_signal'}, sub { $got_sig_quit = clock_gettime(CLOCK_MONOTONIC); });
    }

    my $child_child_pid;

    while (!$child_finished) {
      my $now = clock_gettime(CLOCK_MONOTONIC);

      if ($opts->{'terminate_on_parent_sudden_death'}) {
        $opts->{'runtime'}->{'last_parent_check'} = 0
          unless defined($opts->{'runtime'}->{'last_parent_check'});

        # check for parent once each five seconds
        if ($now - $opts->{'runtime'}->{'last_parent_check'} > 5) {
          if (getppid() eq "1") {
            kill_gently ($pid, {
              'first_kill_type' => 'process_group',
              'final_kill_type' => 'process_group',
              'wait_time' => $opts->{'terminate_wait_time'}
              });
            $parent_died = 1;
          }

          $opts->{'runtime'}->{'last_parent_check'} = $now;
        }
      }

      # user specified timeout
      if ($opts->{'timeout'}) {
        if ($now - $start_time > $opts->{'timeout'}) {
          kill_gently ($pid, {
            'first_kill_type' => 'process_group',
            'final_kill_type' => 'process_group',
            'wait_time' => $opts->{'terminate_wait_time'}
            });
          $child_timedout = 1;
        }
      }

      # give OS 10 seconds for correct return of waitpid,
      # kill process after that and finish wait loop;
      # shouldn't ever happen -- remove this code?
      if ($got_sig_child) {
        if ($now - $got_sig_child > 10) {
          print STDERR "waitpid did not return -1 for 10 seconds after SIG_CHLD, killing [$pid]\n";
          kill (-9, $pid);
          $child_finished = 1;
        }
      }

      if ($got_sig_quit) {
#        Yandex::Tools::do_log("ending process group $pid", {'stderr' => 1});
        kill_gently ($pid, {
          'first_kill_type' => 'process_group',
          'final_kill_type' => 'process_group',
          'wait_time' => $opts->{'terminate_wait_time'}
          });
        $child_finished = 1;
      }

      my $waitpid = waitpid($pid, WNOHANG);

      # child finished, catch it's exit status
      if ($waitpid ne 0 && $waitpid ne -1) {
        $child_exit_code = $? >> 8;
      }

      if ($waitpid eq -1) {
        $child_finished = 1;
        next;
      }

      # child -> parent simple internal communication protocol
      while (my $l = <$child_info_socket>) {
        if ($l =~ /^spawned ([0-9]+?)\n(.*?)/so) {
          $child_child_pid = $1;
          $l = $2;
        }
        if ($l =~ /^reaped ([0-9]+?)\n(.*?)/so) {
          $child_child_pid = undef;
          $l = $2;
        }
        if ($l =~ /^[\d]+ killed with ([0-9]+?)\n(.*?)/so) {
          $child_killed_by_signal = $1;
          $l = $2;
        }
      }

      while (my $l = <$child_stdout_socket>) {
        if (!$opts->{'discard_output'}) {
          $child_stdout .= $l;
          $child_merged .= $l;
        }

        if ($opts->{'stdout_handler'} && ref($opts->{'stdout_handler'}) eq 'CODE') {
          $opts->{'stdout_handler'}->($l);
        }
      }
      while (my $l = <$child_stderr_socket>) {
        if (!$opts->{'discard_output'}) {
          $child_stderr .= $l;
          $child_merged .= $l;
        }

        if ($opts->{'stderr_handler'} && ref($opts->{'stderr_handler'}) eq 'CODE') {
          $opts->{'stderr_handler'}->($l);
        }
      }

      Time::HiRes::usleep(1);
    }

    # $child_pid_pid is not defined in two cases:
    #  * when our child was killed before
    #    it had chance to tell us the pid
    #    of the child it spawned. we can do
    #    nothing in this case :(
    #  * our child successfully reaped its child,
    #    we have nothing left to do in this case
    #
    # defined $child_pid_pid means child's child
    # has not died but nobody is waiting for it,
    # killing it brutally.
    #
    if ($child_child_pid) {
      kill_gently($child_child_pid);
    }

    # in case there are forks in child which
    # do not forward or process signals (TERM) correctly
    # kill whole child process group, effectively trying
    # not to return with some children or their parts still running
    #
    # to be more accurate -- we need to be sure
    # that this is process group created by our child
    # (and not some other process group with the same pgid,
    # created just after death of our child) -- fortunately
    # this might happen only when process group ids
    # are reused quickly (there are lots of processes
    # spawning new process groups for example)
    #
    if ($opts->{'clean_up_children'}) {
      kill(-9, $pid);
    }

#    print "child $pid finished\n";

    close($child_stdout_socket);
    close($child_stderr_socket);
    close($child_info_socket);

    my $o = {
      'stdout' => $child_stdout,
      'stderr' => $child_stderr,
      'merged' => $child_merged,
      'timeout' => $child_timedout ? $opts->{'timeout'} : 0,
      'exit_code' => $child_exit_code,
      'parent_died' => $parent_died,
      'killed_by_signal' => $child_killed_by_signal,
      'child_pgid' => $pid,
      };

    my $err_msg = "";
    if ($o->{'exit_code'}) {
      $err_msg .= "exited with code [$o->{'exit_code'}]\n";
    }
    if ($o->{'timeout'}) {
      $err_msg .= "ran more than [$o->{'timeout'}] seconds\n";
    }
    if ($o->{'parent_died'}) {
      $err_msg .= "parent died\n";
    }
    if ($o->{'stdout'} && !$opts->{'non_empty_stdout_ok'}) {
      $err_msg .= "stdout:\n" . $o->{'stdout'} . "\n";
    }
    if ($o->{'stderr'}) {
      $err_msg .= "stderr:\n" . $o->{'stderr'} . "\n";
    }
    if ($o->{'killed_by_signal'}) {
      $err_msg .= "killed by signal [" . $o->{'killed_by_signal'} . "]\n";
    }
    $o->{'err_msg'} = $err_msg;

    if ($orig_sig_child) {
      $SIG{'CHLD'} = $orig_sig_child;
    }
    else {
      delete($SIG{'CHLD'});
    }

    return $o;
  }
  else {
    Yandex::Tools::die("cannot fork: $!") unless defined($pid);

    # create new process session for open3 call,
    # so we hopefully can kill all the subprocesses
    # which might be spawned in it (except for those
    # which do setsid theirselves -- can't do anything
    # with those)

    POSIX::setsid() || Yandex::Tools::die("Error running setsid: " . $!);

    if ($opts->{'child_BEGIN'} && ref($opts->{'child_BEGIN'}) eq 'CODE') {
      $opts->{'child_BEGIN'}->();
    }

    close($child_stdout_socket);
    close($child_stderr_socket);
    close($child_info_socket);

    my $child_exit_code;

    # allow both external programs
    # and internal perl calls
    if (!ref($cmd)) {
      $child_exit_code = open3_run($cmd, {
        'parent_info' => $parent_info_socket,
        'parent_stdout' => $parent_stdout_socket,
        'parent_stderr' => $parent_stderr_socket,
        'child_stdin' => $opts->{'child_stdin'},
        });
    }
    elsif (ref($cmd) eq 'CODE') {
      $child_exit_code = $cmd->({
        'opts' => $opts,
        'parent_info' => $parent_info_socket,
        'parent_stdout' => $parent_stdout_socket,
        'parent_stderr' => $parent_stderr_socket,
        'child_stdin' => $opts->{'child_stdin'},
        });
    }
    else {
      print $parent_stderr_socket "Invalid command reference: " . ref($cmd) . "\n";
      $child_exit_code = 1;
    }

    close($parent_stdout_socket);
    close($parent_stderr_socket);
    close($parent_info_socket);

    if ($opts->{'child_END'} && ref($opts->{'child_END'}) eq 'CODE') {
      $opts->{'child_END'}->();
    }

    exit $child_exit_code;
  }
}

sub debug2 {
  my ($text, $opts) = @_;
  
  if ($Yandex::Tools::debug2) {
    debug($text, $opts);
  }
}

sub debug {
  my ($text, $opts) = @_;

  $opts = {} unless $opts;

  if ($Yandex::Tools::debug) {
    my $stamp = localtime() . ": ";

    utf8::encode($text) if utf8::is_utf8($text);
    
    if ($opts->{'stderr'}) {
      if (ref($text)) {
        print STDERR join("", map { "$stamp$_\n" } Dumper($text));
      }
      else {
        print STDERR $stamp . ($text ? $text : "") .
          ($text =~ /[\r\n]$/so ? "" : "\n");
      }
    }
    else {
      if (ref($text)) {
        print join("", map { "$stamp$_\n" } Dumper($text));
      }
      else {
        print $stamp . ($text ? $text : "") .
          ($text =~ /[\r\n]$/so ? "" : "\n");
      }
    }
  }
}

# safe_open and safe_close are copied
# from ps_farm.pm (should be one library actually)
sub safe_open {
  my ($filename, $mode, $opts) = @_;

  $opts = {} unless $opts;
  $opts->{'timeout'} = 30 unless defined($opts->{'timeout'});

  $mode = "open" unless $mode;

  if ($mode eq "overwrite" || $mode eq ">") {
    $mode = ">";
  }
  elsif ($mode eq "append" || $mode eq ">>") {
    $mode = ">>";
  }
  else {
    $mode = "";
  }

  my $fh;
  my $i=0;
  while (! open($fh, "${mode}${filename}")) {
    $i = $i + 1;
    if ($i > $opts->{'timeout'}) {
      print STDERR "Unable to open $filename\n" if ! $opts->{'silent'};
      return 0;
    }

    print STDERR "still trying to open $filename\n" if ! $opts->{'silent'};
    sleep 1;
  }

  # http://perldoc.perl.org/functions/flock.html
  #
  # LOCK_SH, LOCK_EX, LOCK_UN, LOCK_NB <=> 1, 2, 8, 4
  #
  # If LOCK_NB is bitwise-or'ed with LOCK_SH or LOCK_EX
  # then flock will return immediately

  while (! flock($fh, 2 | 4)) {
    $i = $i + 1;
    if ($i > $opts->{'timeout'}) {
      print STDERR "Unable to lock $filename\n" if ! $opts->{'silent'};
      return 0;
    }

    print STDERR "still trying to lock $filename\n" if ! $opts->{'silent'};
    sleep 1;
  }

  my $fh1;
  if (!open($fh1, "${mode}${filename}")) {
    $i = $i + 1;
    if ($i > $opts->{'timeout'}) {
      print STDERR "Unable to open and lock $filename\n" if ! $opts->{'silent'};
      return 0;
    }

    print STDERR "Locked $filename, but it's gone. Retrying...\n" if ! $opts->{'silent'};
    $opts->{'timeout'} = $opts->{'timeout'} - 1;
    return safe_open($filename, $mode, $opts);
  }
  else {
    close($fh1);
    return $fh;
  }
}

sub safe_close {
  my ($fh) = @_;
  return flock($fh, 8) && close($fh);
}

sub set_log_options {
  my ($opts) = @_;
  
  $Yandex::Tools::LOG = {}
    unless $Yandex::Tools::LOG;

  foreach my $k (keys %{$opts}) {
    $Yandex::Tools::LOG->{$k} = $opts->{$k};
  }
}

sub get_log_options {
  if ($Yandex::Tools::LOG) {
    return Storable::dclone($Yandex::Tools::LOG);
  }
  return undef;
}

sub set_log_filename {
  my ($filename, $opts) = @_;

  if ($Yandex::Tools::LOG) {
    if (ref($Yandex::Tools::LOG)) {
      $Yandex::Tools::LOG->{'filename'} = $filename;
    }
    else {
      $Yandex::Tools::LOG = $filename
    }
  }
  else {
    $Yandex::Tools::LOG = {
      'filename' => $filename,
      };
  }
}

sub get_log_filename {
  if (ref($Yandex::Tools::LOG)) {
    return $Yandex::Tools::LOG->{'filename'};
  }
  else {
    return $Yandex::Tools::LOG;
  }
}

sub do_log {
    my ($message, $opts) = @_;
    
    my $module;
    my $stderr = 0;
    
    # old style $module population
    #
    if (ref($opts) eq 'HASH') {
      if ($opts->{'module'}) {
        $module = $opts->{'module'};
      }
      if ($opts->{'stderr'}) {
        $stderr = $opts->{'stderr'};
      }
    }
    else {
      $module = $opts;
    }

    # current program name (if all previous methods
    # did not return meaningful module identification)
    #
    $module = $0 unless $module;

    # module name formatting
    #
    $module = "[" . $module . "] " if $module;


    $message = "" unless $message;
    utf8::encode($message) if utf8::is_utf8($message);
    $message =~ s/[\r\n]/ /sgo;

    my $message_eol = chop($message);
    my $message_formatted =
      localtime() . " " . $module .
      $message .
      $message_eol .
      ($message_eol eq "\n" ? "" : "\n");
    
    if ($stderr) {
      print STDERR $message_formatted;
    }
    elsif ($Yandex::Tools::debug) {
      print $message_formatted;
    }
    
    my $log_filename;
    my $log_dirname;

    if (!defined($Yandex::Tools::LOG)) {
      print STDERR "Yandex::Tools::LOG not configured: $message_formatted\n";
      return;
    }
    if (ref($Yandex::Tools::LOG)) {
      if ($Yandex::Tools::LOG->{'turned_off'}) {
        return;
      }

      $log_filename = $Yandex::Tools::LOG->{'filename'};
      if (!$log_filename) {
        print STDERR "Yandex::Tools::LOG->{'filename'} not configured: $message_formatted\n";
        return;
      }
    }
    else {
      $log_filename = $Yandex::Tools::LOG;
    }

    if (!can_write($log_filename)) {
      print STDERR "$log_filename is not writeable: $message_formatted\n";
      return;
    }

    $log_dirname = dirname($log_filename);
    if (! -d $log_dirname) {
      File::Path::mkpath($log_dirname) ||
        return Yandex::Tools::warn("[$log_filename] does not exist and unable to create [$log_dirname]");
    }

    if (ref($Yandex::Tools::LOG) && $Yandex::Tools::LOG->{'rotate_size'}) {
      # quick check that we might need to do rotation
      my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
       $atime,$mtime,$ctime,$blksize,$blocks) = stat($log_filename);

      if ($size && $size > $Yandex::Tools::LOG->{'rotate_size'}) {

        my $rotated = 0;
        
        # if it seems that rotation is needed -- lock file
        # and retry (someone might already done that)
        my $rfh = safe_open($log_filename, "");
        Yandex::Tools::die ("Unable to open $log_filename; log message: $message_formatted", {'no_log' => 1})
          unless $rfh;

        ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
         $atime,$mtime,$ctime,$blksize,$blocks) = stat($log_filename);
        if ($size && $size > $Yandex::Tools::LOG->{'rotate_size'}) {
          link($log_filename, $log_filename . "." . time()) && unlink($log_filename) && ($rotated = 1);
        }
        else {
#          print "already rotated!\n";
        }
        safe_close($rfh);

        if ($rotated && $Yandex::Tools::LOG->{'rotate_keep_copies'}) {
          my $dummy;
          if (!opendir($dummy, $log_dirname)) {
            Yandex::Tools::warn("unable to open log directory [$log_dirname] during log rotation");
          }
          else {
            my @all_entries = readdir($dummy);
            close($dummy);
          
            my $log_archive_count = 0;
            foreach my $e (sort {$b cmp $a} @all_entries) {
              next if "$log_dirname/$e" !~ /$log_filename\.[0-9]+$/;
              next if ! -e "$log_dirname/$e";

              $log_archive_count = $log_archive_count + 1;
              if ($log_archive_count > $Yandex::Tools::LOG->{'rotate_keep_copies'}) {
                unlink("$log_dirname/$e") || Yandex::Tools::warn("unable to delete expired log archive [$log_dirname/$e]");
              }
            }
          }
        }
      }
    }

    my $fh = safe_open($log_filename, ">>");
    Yandex::Tools::die ("Unable to open $log_filename; log message: $message_formatted", {'no_log' => 1})
      unless $fh;

#    binmode($fh, ":utf8");
    print $fh $message_formatted;
    safe_close($fh);
}

# are we able to write to file
sub can_write {
  my ($filename) = @_;

  if (! -d dirname($filename)) {
    if (!File::Path::mkpath(dirname($filename))) {
      return 0;
    }
  }

  if (-e $filename) {
    if (-w $filename) {
      return 1;
    }
    else {
      return 0;
    }
  }
  else {
    my $fh = safe_open($filename, ">", {"timeout" => 0, "silent" => 1});
    if ($fh) {
      safe_close($fh);
      return 1;
    }
    else {
      return 0;
    }
  }
}

# are we able to log
sub can_log {
  if (defined($Yandex::Tools::LOG)) {
    my $log_filename;
    if (ref($Yandex::Tools::LOG)) {
      $log_filename = $Yandex::Tools::LOG->{'filename'};
      if (!$log_filename) {
        $Yandex::Tools::LOG = undef;
        return 0;
      }
    }
    else {
      $log_filename = $Yandex::Tools::LOG;
    }

    if (!can_write($log_filename)) {
      $Yandex::Tools::LOG = undef;
      return 0;
    }
  }

  return 1;
}

sub add_hook {
  my ($opts) = @_;

  Yandex::Tools::die("add_hook: invalid input")
    unless $opts->{'type'} &&
      ref($opts->{'func'}) eq 'CODE' &&
      ref($opts->{'args'}) eq 'ARRAY';
  
  push @{$Yandex::Tools::HOOKS->{$opts->{'type'}}}, {
    'func' => $opts->{'func'},
    'args' => $opts->{'args'},
    };
}

sub run_hook {
  my ($type) = @_;

  if (scalar(@{$Yandex::Tools::HOOKS->{$type}}) gt 0) {
    my $h = pop(@{$Yandex::Tools::HOOKS->{$type}});
    $h->{'func'}->(@{$h->{'args'}});
  }
}

sub run_hooks {
  my ($type) = @_;

  while (scalar(@{$Yandex::Tools::HOOKS->{$type}}) gt 0) {
    Yandex::Tools::run_hook($type);
  }
}

sub warn {
  my ($text) = @_;
  print STDERR "WARNING: $text\n";
  Yandex::Tools::do_log("[WARN] " . $text);
}

sub die {
  my ($message, $opts) = @_;

  $opts = {} unless $opts;

  # backward compatibility (second parameter used to be scalar)
  if (!ref($opts)) {
    $opts->{'show_callstack'} = 1;
  }

  if ($Yandex::Tools::HOOKS->{'before_die'} && scalar(@{$Yandex::Tools::HOOKS->{'before_die'}})) {
    Yandex::Tools::run_hooks("before_die");
  }
  
  print STDERR ($message ? $message : "");

  if ($opts->{'show_callstack'}) {
    print STDERR get_callstack();
  }
  else {
    print "\n";
  }

  if (!$opts->{'no_log'}) {
    Yandex::Tools::do_log("[ERR] " . $message);
  }
  else {
    # try logger here?
  }

  exit 1;
}

sub get_callstack {
  my $cstack = "";
  my $i = 0;
  while ( 1 ) {
    my $tfunc = (caller($i))[3];
    if ($tfunc && $tfunc ne "") {
      if ($tfunc !~ /\_\_ANON\_\_/ &&
        $tfunc !~ /.*::get_callstack/) {
        $cstack .= "\t" . $tfunc . "\n";
      }
      $i = $i + 1;
    }
    else {
      last;
    }
  }
  return "\nCallstack:\n" . $cstack . "\n";
}

sub read_cmdline {
  my $i = 0;

  $new_cmd_opts = {};

  my $v;
  my $first_parameter;
  while ($ARGV[$i]) {
    if ($ARGV[$i] =~ /--(.+)\b/) {
      $v = $1;
      if ($v eq "debug") {
        $debug = 1;
      }
      elsif ($v eq "debug2") {
        $debug = 1;
        $debug2 = 1;
      }
      else {
        $command = $v unless $command;

        $cmd_opts->{$v} = "";
        $first_parameter = 1;
      }

      $new_cmd_opts->{$v} = {
        'defined' => 1,
        'value' => '',
        };
    }
    else {
      if ($v) {
        if ($first_parameter) {
          $cmd_opts->{$v} = "";
          $first_parameter = 0;
        }

        $cmd_opts->{$v} .= ($cmd_opts->{$v} ? " " : "") . $ARGV[$i];

        $new_cmd_opts->{$v}->{'value'} .=
          ($new_cmd_opts->{$v}->{'value'} ? " " : "") . $ARGV[$i];
      }
      else {
        $cmd_opts->{$ARGV[$i]} = 1;

        $new_cmd_opts->{$ARGV[$i]} = {
          'defined' => 1,
          'value' => '',
          };
      }
    }
    $i++;
  }
}

sub defined_cmdline_param {
  my ($pname) = @_;

  if (!ref($new_cmd_opts)) {
    croak("Programmer error: get_cmdline_param called without read_cmdline");
  }

  return defined($new_cmd_opts->{$pname});
}

sub get_cmdline_param {
  my ($pname) = @_;

  if (!ref($new_cmd_opts)) {
    croak("Programmer error: get_cmdline_param called without read_cmdline");
  }

  if ($pname) {
    if ($new_cmd_opts->{$pname}) {
      return $new_cmd_opts->{$pname}->{'value'};
    }
    else {
      return undef;
    }
  }
  else {
    return $new_cmd_opts;
  }
}

sub num_cmdline_param {
  return scalar(keys %{$new_cmd_opts});
}

sub canonize_delimiters {
  my ($str, $except) = @_;

  my $delimiters = "ts,;&";

  my $delimiters_prepared;
  foreach my $d (split(//, $delimiters)) {
    next if $except && $except =~ /$d/;
    $delimiters_prepared = $delimiters_prepared . "\\$d"
  }
  
  my $delim_re = qr/[$delimiters_prepared]+/;
  $$str =~ s/$delim_re/\ /g;
}

# - removes duplicates from array
# - leaves first occurence of each duplicate
# - preserves order
# - valid only for arrays of scalars and arrayrefs
#
sub array_clear_dupes {
  my @array_in = @_;

  my @array_to_process;
  foreach my $e (@array_in) {
    if (ref($e) eq 'ARRAY') {
      push (@array_to_process, @{$e});
    }
    else {
      push (@array_to_process, $e);
    }
  }

  my @array_out;
  my $c = {};
  foreach my $e (@array_to_process) {
    unless ($c->{$e}) {
      $c->{$e} = 1;
      push (@array_out, $e);
    }
  }
  
  return @array_out;
}

# <LJFUNC>
# name: LJ::is_ascii
# des: checks if text is pure ASCII.
# args: text
# des-text: text to check for being pure 7-bit ASCII text.
# returns: 1 if text is indeed pure 7-bit, 0 otherwise.
# </LJFUNC>
sub is_ascii {
    my $text = shift;
    return ($text !~ m/[^\x01-\x7f]/o);
}

sub is_digital {
  my $text = shift;
  return ( $text =~ /^\d+$/o );
}

sub QP {
  my ($text, $encoding) = @_;
  
  $text = "" unless $text;

  $encoding = "UTF-8" unless $encoding;

  my $encoded_text = $text;

  if ($encoding eq "UTF-8") {
    $encoded_text = encode("utf8", $encoded_text);
  }

  $encoded_text = encode_base64($encoded_text, "");
  $encoded_text = "=?${encoding}?B?$encoded_text?=";

#  $encoded_text = encode_qp($text);
#  $encoded_text = "=?${encoding}?Q?$encoded_text?=";
  
  return $encoded_text;
}

# should be used when you need to concatenate string
# which might be undefined and you want empty string ("")
# instead of perl warnings about uninitialized values
#
sub safe_string {
  my ($str) = @_;

  if (defined($str)) {
    return $str;
  }
  else {
    return "";
  }
}

#
# generic mail sending function
#
# expects one input parameter, hashref, with following keys:
#
#   to          [mandatory] -- comma-separated list or arrayref of recipients
#   from        [optional]  -- string
#   cc          [optional]  -- comma-separated list or arrayref
#   bcc         [optional]  -- comma-separated list or arrayref
#   subject     [optional]  -- string
#   data        [optional]  -- string, message body
#   charset     [optional]  -- string, utf-8 by default
#   attach      [optional]  -- scalar (might be binary)
#   attach_name [optional]  -- string, attachment name
#   headers     [optional]  -- hashref { header_name => header_value }
#
sub send_mail {
  my ($opts) = @_;

  Yandex::Tools::die("Programmer error: send_mail expects hashref with at least 'to' set")
    unless $opts && $opts->{'to'};
  
  foreach my $att (qw /subject body cc bcc/) {
    $opts->{$att} = "" unless defined($opts->{$att});
  }
  $opts->{'charset'} = "utf-8" unless $opts->{'charset'};

  my $process_emails_to_array = sub {
    my ($a) = @_;

    my @b;
    if (ref($a) eq 'ARRAY') {
      @b = @{$a};
    }
    else {
      Yandex::Tools::canonize_delimiters(\$a);
      @b = split(/\ /, $a);
    }

    return \@b;
  };

  my $process_emails_to_string = sub {
    my ($a) = @_;

    if (ref($a) eq 'ARRAY') {
      return join(",", @{$a});
    }
    else {
      return $a;
    }
  };

  foreach my $f (qw/to cc bcc/) {
    $opts->{$f} = $process_emails_to_array->($opts->{$f});
  }

  push (@{$opts->{'cc'}}, $Yandex::Tools::CC_ALL) if $Yandex::Tools::CC_ALL && !$opts->{'no_cc_all'};
  push (@{$opts->{'bcc'}}, $Yandex::Tools::BCC_ALL) if $Yandex::Tools::BCC_ALL && !$opts->{'no_bcc_all'};

  foreach my $f (qw/to cc bcc/) {
    my @a = Yandex::Tools::array_clear_dupes($opts->{$f});
    $opts->{$f} = $process_emails_to_string->(\@a);
  }
   
  $opts->{'from'} = $Yandex::Tools::MAIL_FROM
    unless $opts->{'from'};

  my @log_to;
  my $clean_emails = sub {
    my ($in) = @_;
    my @out;

    foreach my $e (split /,/, $in) {
      $e =~ s/^.*<//o;
      $e =~ s/>.*$//o;
      push(@out, $e);
    }

    return join(",", @out);
  };
  foreach my $f (qw/from to cc bcc/) {
    push @log_to, "$f: " . $clean_emails->($opts->{$f}) if $opts->{$f};
  }

  if ($have_mime_lite) {
    my $msg = new MIME::Lite (
      'From' => $opts->{'from'},
      'To' => $opts->{'to'},
      'Cc' => $opts->{'cc'},
      'Bcc' => $opts->{'bcc'},
      'Subject' => QP($opts->{'subject'}, $opts->{'charset'}),
      'Data' => $opts->{'body'},
      );

  #  $opts->{'headers'}->{'Reply-To'} = $Golem::SUPPORT_EMAIL
  #    if $Golem::SUPPORT_EMAIL;

    $msg->attr("content-type.charset" => $opts->{'charset'})
      if $opts->{'charset'} &&
        ! (Yandex::Tools::is_ascii($opts->{'body'}) &&
        Yandex::Tools::is_ascii($opts->{'subject'}));

    if ($opts->{'attach'}) {
      my $mm = new File::MMagic;
      my $attach_type = $mm->checktype_contents($opts->{'attach'});

      my $part = MIME::Lite->new(
        Type     => $attach_type,
        Data     => $opts->{'attach'},
        Filename => $opts->{'attach_name'} ? $opts->{'attach_name'} : undef,
        );
      $msg->attach($part);
    }

    if ($opts->{'headers'}) {
      while (my ($k, $v) = each %{$opts->{'headers'}}) {
        $msg->add($k => $v);
      }
    }

    unless ($msg->send()) {
      Yandex::Tools::do_log("Unable to send mail through MIME::Lite; recipients: [" . join (" ", @log_to) . "]", {"stderr" => 1});
      return 0;
    }
  }
  else {
    my $to_scalar;
    my $subj = $opts->{'subject'} || "";

    $subj =~ s/"/\\"/go;
    
    foreach my $f (qw/to cc/) {
      if ($opts->{$f}) {
        $to_scalar = ($to_scalar ? $to_scalar . "," : "") . $clean_emails->($opts->{$f});
      }
    }

    if ($opts->{'from'}) {
      # for Heirloom mailx 12.4 used on forward*.mail.yandex.net
      $ENV{'from'} = $opts->{'from'};
    }

    my $r = Yandex::Tools::run_forked("mail -s \"$subj\" $to_scalar", {'child_stdin' => $opts->{'body'}});
    if ($r->{'exit_code'} ne 0) {
      Yandex::Tools::do_log("Unable to send mail through system mailer, exit_code [$r->{'exit_code'}], stderr [$r->{'stderr'}], " .
        "to [$to_scalar], message [" . substr($opts->{'body'}, 0, 200) . "] ", {"stderr" => 1});
      return 0;
    }
  }

  if ($Yandex::Tools::LOG) {
    Yandex::Tools::do_log("sent mail " . join (" ", @log_to));
  }

  return 1;
}

# checks if $str matches one of $rfx (arrayref)
#
sub matches_with_one_of_regexps {
  my ($str, $rxs) = @_;

  $rxs = [] if !$rxs || ref($rxs) ne 'ARRAY';

  foreach my $rx (@{$rxs}) {
    next if !defined($rx);

    if ($str =~ /$rx/) {
      return 1;
    }
  }

  return 0;
}

sub daemonize {
  chdir('/') 
    or CORE::die "Can not chdir to '/': $!\n";

  open(STDIN, '/dev/null') 
    or CORE::die "Can not read /dev/null: $!\n";

  open(STDOUT, '/dev/null')
    or CORE::die "Can not write to /dev/null: $!\n";
 
  defined(my $pid = fork)
    or CORE::die "Can not fork: $!\n";

  exit if $pid;

  POSIX::setsid()
    or CORE::die("Error running setsid: " . $!);

  open(STDERR, "/dev/null")
    or CORE::die("unable to bind stderr to /dev/null: $!");
}

# fork && exec, replace myself with new myself,
# possibly reading in my new version
sub exec {
  my ($cmd) = @_;

  if (my $pid = fork) {
    if (!$pid) {
      Yandex::Tools::die("unable to fork: " . $!);
    }

    # parent
    exit 0;
  }
  else {
    POSIX::setsid() || Yandex::Tools::die("Error running setsid: " . $!);

    # let parent exit and clean up from /proc (or whatever)
    sleep 1;

    POSIX::setsid() || Yandex::Tools::do_log("Error running setsid: " . $!, {'stderr' => 1}) && CORE::die();
    
    # next life
    exec($cmd) || Yandex::Tools::do_log("[$$] unable to exec $cmd", {'stderr' => 1}) && CORE::die();
  }
  exit(255);
}


sub lock {
  my ($file) = @_;

  Yandex::Tools::die("lock: lock name expected") unless $file;

  $Yandex::Tools::locks = {} unless $Yandex::Tools::locks;

  $Yandex::Tools::locks->{$file} = Yandex::Tools::safe_open($file, "overwrite", {'silent' => 1, 'timeout' => 5});
  return undef unless $Yandex::Tools::locks->{$file};

  my $lock_fh = $Yandex::Tools::locks->{$file};
  autoflush $lock_fh;
  print $lock_fh $$;

  Yandex::Tools::add_hook({
    'type' => 'before_die',
     'func' => sub {Yandex::Tools::unlock($file);},
     'args' => [],
     });

  return 1;
}

sub unlock {
  my ($file) = @_;

  Yandex::Tools::die("unlock: lock name expected") unless $file;

  if ($Yandex::Tools::locks->{$file}) {
    Yandex::Tools::safe_close($Yandex::Tools::locks->{$file});
    unlink($file);
    $Yandex::Tools::locks->{$file} = undef;
    return 1;
  }

  return undef;
}

sub is_locked {
  my ($file) = @_;

  Yandex::Tools::die("is_locked: lock name expected") unless $file;

  if (! -e $file) {
    return 0;
  }

  $Yandex::Tools::locks->{$file} = Yandex::Tools::safe_open($file, "",
    {
      'silent' => 1,
      'timeout' => 0,
    });

  if ($Yandex::Tools::locks->{$file}) {
    Yandex::Tools::safe_close($Yandex::Tools::locks->{$file});
    $Yandex::Tools::locks->{$file} = undef;
    return 0;
  }
  else {
    return Yandex::Tools::read_file_scalar($file);
  }
}



1;

__END__

=head1 NAME

Yandex::Tools - useful functions for Yandex daemons and programs.

=head1 LOGGING

  use Yandex::Tools qw(/^/);

  # logging
  set_log_filename("/var/log/mylog");
  if (!can_log()) {
    die ("can't log!\n");
  }

  print "will log to: " . get_log_filename() . "\n";

  set_log_options({
    'rotate_size' => 1024*1024, # 1MB
    'rotate_keep_copies' => 2,
  });

  do_log("yoyo");

=head1 FILESYSTEM

  use Yandex::Tools qw(/^/);

  # test if you can write file (by creating it)
  if (!can_write("/root/test123")) {
    die "can't write to /root\n!";
  }

  # read text file into array of lines, removing \r\n
  my $f = read_file_array('/etc/passwd');
  foreach my $line (@{$f}) {
    print $line . "\n";
  }

  # read file removing \r\n; returns undef if file doesn't exist
  my $hostname = read_file_option('/etc/hostname');

  # read file as is; returns undef if file doesn't exist
  my $etc_passwd = read_file_scalar('/etc/passwd');

  # read file as is; returns True on success, False otherwise
  if (write_file_scalar('/etc/passwd', $etc_passwd)) {
    print "written successfully!\n";
  }

  # simply write some text to file
  # (which would be read with read_file_option)
  if (!write_file_option('/tmp/hostname', 'test')) {
    die "unable to write /tmp/hostname!";
  }

  # get filesystem object struct (fileinfo struct)
  #
  # $VAR1 = {
  #   'uid' => 0,
  #   'short_name' => 'passwd',
  #   'mtime' => 1273586736,
  #   'mode' => 420,
  #   'size' => 1081,
  #   'absolute_name' => '/etc/passwd',
  #   'relative_name' => 'etc/passwd',
  #   'type' => 'file',
  #   'gid' => 0
  #   };
  #
  my $fs_obj = fileinfo_struct({'absolute_name' => '/etc/passwd'});

  # read directory entries into array (by default)
  # of fileinfo structs (see above), does not recurse
  # into directories, allows optional filtering
  # of only-files or only-directories
  #
  my $mixed_array = read_dir('/etc', {'output_type' => 'arrayref', 'only-directories' => 1});

  # read directory into hash (recursive),
  # with relative entry name as a key
  # and fileinfo struct as value
  #
  my $dir_struct = read_dir('/etc', {'output_type' => 'hashref'});

=head1 STRINGS

  use Yandex::Tools qw(/^/);

  # remove duplicate entries from array
  #
  my @arr = qw/1 2 3 4 5 1 2 3 4 5/;
  my @uniq = array_clear_dupes(@arr);
  print join(",", @uniq) . "\n";

  # prints:
  # 1,2,3,4,5

  # replace all kinds of delimiters like
  # multiple spaces, tabs, commas, ampersands, semicolons
  # with just one space
  my $str = canonize_delimiters($str);

  # self explained:
  if (!is_ascii(chr(1)) || !is_digital(chr(1))) {
    die "oops";
  }

  # match any of regexp
  if (matches_with_one_of_regexps("something", ["one", "two", "some"])) {
    print "match!\n";
  }

  # allows to print anything without warnings
  # even with `use warnings`. replaces undefined values
  # with empty string
  #
  print safe_string(undef);

=head1 OTHER

  # print callstack (for debugging)
  #
  print get_callstack();

  # release candidate version of run_forked,
  # cool external programs execution routine
  # allowing time limiting and some other
  # types of control.
  #
  # distributed widely in L<IPC::Cmd>,
  # read documentation there.
  #
  my $r = run_forked("uptime");
  print $r->{'stdout'};

  # send mail (different mailers are tried)
  #
  send_mail({
    'to' => 'root',
    'subject' => 'test',
    'body' => 'test',
    });

=head1 AUTHORS

Petya Kohts E<lt>petya@kohts.ruE<gt>

=head1 COPYRIGHT

Copyright 2007 - 2011 Petya Kohts.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
