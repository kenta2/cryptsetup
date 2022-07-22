package Cryptsetup::Mock;

# Mock terminal interaction on a guest system
#
# Copyright © 2021-2022 Guilhem Moulin <guilhem@debian.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use v5.14.2;
use warnings;
use strict;

use Socket qw/PF_UNIX SOCK_STREAM SOCK_CLOEXEC SOCK_NONBLOCK SHUT_RD SHUT_WR/;
use Errno qw/EINTR ENOENT ECONNREFUSED/;
use Time::HiRes ();

my (%SOCKET, %BUFFER);
my ($WBITS, $RBITS);
use Exporter qw/import/;
BEGIN {
    my $dir = $ARGV[1] =~ m#\A(/\p{Print}+)\z# ? $1 : die "Invalid base directory\n"; # untaint
    my $epoch = Time::HiRes::time();
    foreach my $id (qw/mon0 ttyS0/) {
        my $path = $dir . "/" . $id;
        my $sockaddr = Socket::pack_sockaddr_un($path) // die;
        socket(my $socket, PF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) or die "socket: $!";

        until (connect($socket, $sockaddr)) {
            if ($! == EINTR) {
                # try again immediatly if connect(2) was interrupted by a signal
            } elsif (($! == ENOENT or $! == ECONNREFUSED) and Time::HiRes::time() - $epoch < 30) {
                # wait a bit to give QEMU time to create the socket and mark it at listening
                Time::HiRes::usleep(100_000);
            } else {
                die "connect($path): $!";
            }
        }

        my $fd = fileno($socket) // die;
        vec($WBITS, $fd, 1) = 1;
        vec($RBITS, $fd, 1) = 1;
        $SOCKET{$id} = $socket;
        $BUFFER{$id} = "";
    }

    our @EXPORT = qw/
        expect
        unlock_disk
        login
        login_nopassword
        type_password
        type_at_prompt
        shell_command
        shell_command2
        assert_command
        poweroff
        hibernate
    /;
}

my $SERIAL = "ttyS0";
sub read_data($) {
    my $bits = shift;
    while (my ($chan, $fh) = each %SOCKET) {
        next unless vec($bits, fileno($fh), 1); # nothing to read here
        my $n = sysread($fh, my $buf, 4096) // die "read: $!";
        if ($n > 0) {
            STDOUT->printflush($buf);
            $BUFFER{$chan} .= $buf;
        } else {
            #print STDERR "INFO done reading from $chan\n";
            shutdown($fh, SHUT_RD) or die "shutdown: $!";
            vec($RBITS, fileno($fh), 1) = 0;
        }
    }
}
sub expect(;$$) {
    my ($chan, $prompt) = @_;

    my $buffer = \$BUFFER{$chan} if defined $chan;
    return wantarray ? %+ : undef if defined $buffer and $$buffer =~ s/$prompt//;

    while(unpack("b*", $RBITS) != 0) {
        my $rout = $RBITS;
        while (select($rout, undef, undef, undef) == -1) {
            die "select: $!" unless $! == EINTR; # try again immediately if select(2) was interrupted
        }
        read_data($rout);
        return wantarray ? %+ : undef if defined $buffer and $$buffer =~ s/$prompt//;
    }
}
sub wait_for_prompt($$) {
    my ($chan, $prompt) = @_;
    return expect($chan => qr/\A(?:.*?\r\n)?$prompt/aasm);
}

sub type_data($$%) {
    my $chan = shift;
    my $data = shift;

    my %options = @_;
    $options{echo} //= 1;
    $options{eol} //= "\r";
    $options{reol} //= "\r\n";
    my $wdata = $data . $options{eol};

    my $wfh = $SOCKET{$chan} // die;
    my $wfd = fileno($wfh) // die;
    vec(my $win, $wfd, 1) = 1;

    for (my $offset = 0, my $length = length($wdata); $offset < $length;) {
        my $wout = $win;
        while (select(undef, $wout, undef, undef) == -1) {
            die "select: $!" unless $! == EINTR; # try again immediately if select(2) was interrupted
        }
        if (vec($wout, $wfd, 1)) {
            my $n = syswrite($wfh, $wdata, $length - $offset, $offset) // die "write: $!";
            $offset += $n;
        }
    }

    if ($options{echo}) {
        my $buf = \$BUFFER{$chan};
        my $rfh = $SOCKET{$chan} // die;
        my $rfd = fileno($rfh) // die;
        vec(my $rin, $rfd, 1) = 1;

        my $rdata = $data . $options{reol};
        my $rlen = length($rdata);
        while($rlen > 0) {
            my $rout = $rin;
            while (select($rout, undef, undef, undef) == -1) {
                die "select: $!" unless $! == EINTR; # try again immediately if select(2) was interrupted
            }
            read_data($rout);

            my $got = substr($$buf, 0, $rlen);
            my $n = length($got);
            if ($got eq substr($rdata, -$rlen, $n)) {
                $$buf = substr($$buf, $n); # consume the command
                $rlen -= $n;
            } else {
                my $a = substr($rdata, 0, -$rlen) . substr($rdata, -$rlen, $n);
                my $b = substr($rdata, 0, -$rlen) . $got;
                s/[^\p{Graph} ]/"\\x".unpack("H*",$&)/ge foreach ($a, $b);
                die "Wanted \"$a\", got \"$b\"";
            }
        }
    }
}

sub type_at_prompt($$%) {
    my ($prompt, $data, %options) = @_;
    wait_for_prompt($SERIAL => $prompt);
    type_data($SERIAL => $data, %options);
}
sub type_password($$%) {
    my ($prompt, $password, %options) = @_;
    type_at_prompt($prompt => $password, %options, echo => 0);
}

my $CSI = qr/\x1B\[ [\x30-\x3F]* [\x20-\x2F]* [\x40-\x7E] /x; # control sequence introducer
my $PS1 = qr/$CSI? root\@[\-\.0-9A-Z_a-z]+ : [~\/][\-\.\/0-9A-Z_a-z]* [\#\$]\ /aax;
my $COMMAND_OUTPUT = qr/\A$CSI? \r (?<result>.*?\r\n)? (?<rest>$PS1) /msx;

sub shell_command($) {
    my $command = shift;
    wait_for_prompt($SERIAL => $PS1);
    type_data($SERIAL => $command);
    my %r = expect($SERIAL => $COMMAND_OUTPUT);
    $BUFFER{$SERIAL} = $r{rest} . $BUFFER{$SERIAL}; # reinject prompt into buffered output
    return $r{result} // "";
}
sub shell_command2($) {
    my $out = shell_command(shift);
    my $rv = shell_command("echo \$?");
    return ($rv+0, $out);
}
sub assert_command($;$) {
    my $command = shift;
    my $assert_rv = shift // 0;
    my ($rv, $out) = shell_command2($command);
    die "Command \`$command\` exited with status $rv\n" unless $rv == $assert_rv;
    return $out;
}

sub unlock_disk($) {
    my $passphrase = shift;
    my $console = "ttyS0";
    my %r = wait_for_prompt($console => qr/Please unlock disk (?<name>\p{Graph}+): /);
    if ((my $ref = ref($passphrase)) ne "") {
        my $name = $r{name};
        unless (defined $name) {
            undef $passphrase;
        } elsif ($ref eq "CODE") {
            $passphrase = $passphrase->($name);
        } elsif ($ref eq "HASH") {
            $passphrase = $passphrase->{$name};
        } else {
            die "Unsupported reference $ref";
        }
    }
    die "Unable to unlock, aborting.\n" unless defined $passphrase;
    type_data($console => $passphrase, echo => 0);
}

my $LOGIN_PROMPT = qr/Debian [^\r\n]+ [0-9A-Za-z]+(?:\r\n)+(?<hostname>[[:alnum:]._-]+) login: /aa;
sub login($$) {
    my ($username, $password) = @_;
    type_at_prompt($LOGIN_PROMPT, $username, reol => "\r");
    type_password(qr/Password: / => $password);
}
sub login_nopassword($) {
    my ($username) = @_;
    type_at_prompt($LOGIN_PROMPT, $username, reol => "\r");
}

sub poweroff() {
    # XXX would be nice to use the QEMU monitor here but the guest
    # doesn't seem respond to system_powerdown QMP commands
    wait_for_prompt($SERIAL => $PS1);
    type_data($SERIAL => "echo o >/proc/sysrq-trigger");
    expect(); # wait for QEMU to terminate
}
sub hibernate() {
    wait_for_prompt($SERIAL => $PS1);
    type_data($SERIAL => "echo disk >/sys/power/state");
    expect(); # wait for QEMU to terminate
}

1;
