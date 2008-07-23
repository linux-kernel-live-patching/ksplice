package verbose;

use strict;
use warnings;

our $AUTOLOAD;
our $level = 0;

sub import {
	my ($self, @syms) = @_;
	foreach my $sym (@syms) {
		&make_verbose($sym, (caller)[0]);
	}
}

sub AUTOLOAD {
	&make_verbose($AUTOLOAD, (caller)[0]);
	goto &$AUTOLOAD;
}

sub debugcall {
	my ($name, @args) = @_;
	local $" = ', ';
	print "+ $name(@args)\n" if ($level);
}

sub make_verbose {
	no strict 'refs';
	no warnings qw(redefine prototype);
	my ($sym, $pkg) = @_;
	$sym = "${pkg}::$sym" unless $sym =~ /::/;
	my $name = $sym;
	$name =~ s/.*::// or $name =~ s/^&//;
	my ($sref, $call, $proto);
	if (defined(&$sym)) {
		$sref = \&$sym;
		$call = '&$sref';
		$proto = prototype $sref;
	} else {
		$call = "CORE::$name";
		$proto = prototype $call;
	}
	$proto = '@' unless defined($proto);
	my $code = "package $pkg; sub ($proto) { verbose::debugcall(\"$name\", \@_); $call(\@_); }";
	*{$sym} = eval($code);
}

1;
