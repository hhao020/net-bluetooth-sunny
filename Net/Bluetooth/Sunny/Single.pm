#!/usr/bin/perl

package Net::Bluetooth::Sunny::Single;

use parent 'Net::Bluetooth::Sunny';
use Data::Dumper;
use strict;

sub info {
    my $self = shift;
    return $self->_extract_single($self->SUPER::info(@_));
}

sub energy {
    my $self = shift;
    return $self->_extract_single($self->SUPER::energy(@_));
}

sub dc {
    my $self = shift;
    return $self->_extract_single($self->SUPER::dc(@_));
}

sub ac {
    my $self = shift;
    return $self->_extract_single($self->SUPER::ac(@_));
}

sub frequency {
    my $self = shift;
    return $self->_extract_single($self->SUPER::frequency(@_));
}

sub _extract_single {
    my $self = shift;
    my $data = shift;
    my $addr = $self->{address} || die "Not yet initialized\n";
    my $ret = $data->{$addr} || die "No result for $addr found\n";
    return $ret;
}

1;
