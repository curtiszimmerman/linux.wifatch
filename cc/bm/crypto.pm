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

package bm::crypto;

use strict;

use Math::GMP;
use Digest::SHA;
use Crypt::PK::ECC;
use Crypt::Rijndael;

my $prngc;
my $prngi = 0;
my $prngb = "";

{
	open my $fh, "</dev/urandom";
	sysread $fh, my $buf, 32;
	$prngc = new Crypt::Rijndael $buf, Crypt::Rijndael::MODE_ECB
}

sub randbytes($)
{
	$prngb .= $prngc->encrypt(pack "x8 P", ++$prngi) while $_[0] > length $prngb;

	substr $prngb, 0, $_[0], "";
}

my $pk = new Crypt::PK::ECC \(pack "H*", 'not-the-real-ecdsa-key');

sub ecdsa_sign($)
{
	my ($m) = @_;

	my ($r, $s) = unpack "xx x C/a x C/a", $pk->sign_hash(Digest::SHA::sha256 $m);

	scalar reverse pack "a32 a32", (scalar reverse $s), (scalar reverse $r);
}

my $N = 3328;
my $n = Math::GMP->new(
	'U4qM5d1Fp7hFNsmBbGRejbcTa9XOnvz1zKys4lBto8Ho1Me8dzlyNre1tOQQ50nnw9XLEOAvpqr4z2nFobDnG5xn5hvRDasKhBKF2rcM58o71QBv8E4MS2rWbAMK6KFVMGhiwRst0yWPKxrcjN65kcUjgCvUD0T3g5ac1lMVMgSVg6F7YnZRiTEAUxOC5H8ElgpOTX9AQXenXmRt87DI5qFKF6S9bo2GOFhkAvQ3UxmNxdkMmALusPUSI70KhqhtbaBcX2YJ76Zoi8S2Nsu0MKZivQrpqGoWzE639miDsk9UVj4JYaUVhCJXFr9Hd4hWjuVWTLOHnF5mArSK1CUuQWfBn3KOZPjxw5EOD8dfxNGDC45oIcfRlNitMM1n5gVGvj8EsmMH6JL1mQPvhIupVNH9inu2DB5xoJb9w6q3kDWPtbOjt8m6qgcmDZiSaKnHqaeo41bQAwSSKjrRh0bxRKQiOU2cKhRHbBzkvHOO9DDCuaj4XH8NBnsvZe4z098bYUoLHRx1po1BouqddrifLzZFpG9r5QsAAMp9DH7swhYMWGP',
	62
);
my $d = Math::GMP->new('not-the-real-rsa-key', 62);

sub rsa_sign($)
{
	my ($m) = @_;

	$m = Digest::SHA::sha256($m);

	my $p = randbytes($N - 256) / 8;

	(vec $p, 7, 1) = 0;
	(vec $p, 6, 1) = 1;

	my $h = $p . Digest::SHA::sha256("$p$m");
	$h = Math::GMP->new((unpack "H*", $h), 16);

	my $s = Math::GMP::powm_gmp($h, $d, $n);
	pack "H" . ($N / 4), scalar reverse Math::GMP::get_str_gmp $s, 16;
}

1

