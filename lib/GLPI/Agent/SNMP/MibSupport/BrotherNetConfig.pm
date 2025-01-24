package GLPI::Agent::SNMP::MibSupport::BrotherNetConfig;

use strict;
use warnings;

use parent 'GLPI::Agent::SNMP::MibSupportTemplate';

use GLPI::Agent::Tools;
use GLPI::Agent::Tools::SNMP;

use constant    priority => 5;

# See BROTHER-MIB
use constant    brother => '.1.3.6.1.4.1.2435' ;

use constant    net_peripheral  => brother . '.2.3.9' ;

use constant    printerinfomation   => net_peripheral . '.4.2.1.5.5' ;
use constant    brInfoSerialNumber  => printerinfomation . '.1.0' ;
use constant    brScanCountCounter  => printerinfomation . '.54.2.2.1.3.3';

use constant    brpsWLanName        => brother . '.2.4.3.100.11.1.3';

# Brother NetConfig
use constant    brnetconfig => brother . '.2.4.3.1240' ;
use constant    brconfig    => brnetconfig . '.1' ;

use constant    brpsNodeName            => brconfig . '.1.0' ;
use constant    brpsHardwareType        => brconfig . '.3.0' ;
use constant    brpsMainRevision        => brconfig . '.4.0' ;
use constant    brpsServerDescription   => brconfig . '.12.0' ;

our $mibSupport = [
    {
        name        => "brother-netconfig",
        privateoid  => brpsHardwareType
    }
];

sub getFirmware {
    my ($self) = @_;

    return getCanonicalString($self->get(brpsMainRevision));
}

sub getSnmpHostname {
    my ($self) = @_;

    return getCanonicalString($self->get(brpsNodeName));
}

sub getSerial {
    my ($self) = @_;

    return getCanonicalString($self->get(brInfoSerialNumber));
}

sub getManufacturer {
    my ($self) = @_;

    my $description = getCanonicalString($self->get(brpsServerDescription));
    return unless !empty($description) && $description =~ /^Brother .*$/i;

    return "Brother";
}

sub getModel {
    my ($self) = @_;

    my $device = $self->device;
    if ($device && $device->{MODEL}) {
        $device->{MODEL} =~ s/^Brother\s+//;
        return $device->{MODEL};
    }

    my $description = getCanonicalString($self->get(brpsServerDescription));
    my ($model) = $description =~ /^Brother (.*)$/i;

    return $model;
}

sub getWlanPorts {
    my ($self) = @_;

    my $device = $self->device
        or return;

    # Get list of device ports
    my %ports = %{$device->{PORTS}->{PORT}};  # Shallow copy
    foreach my $key (keys %ports) {
        $ports{$key} = {%{$ports{$key}}};  # Deep copy for one level deep hash
    }
    
    foreach my $port (keys %ports) {
        # Loopback or DOWN interfaces
        if ($ports{$port}->{IFTYPE} == 24 || $ports{$port}->{IFTYPE} == 2) {
            delete $ports{$port};
        }
    }
    
    # Only one interface remaining and actually connected to a WLAN network
    my $brpsWLanName = $self->walk(brpsWLanName);
    if (scalar(keys %ports) == 1 && $brpsWLanName) {
        foreach my $port (keys %ports) {
            # Replaces the port ifType from "Ethernet" to "WiFi" (71)
            if ($ports{$port}->{IFTYPE} == 6 || $ports{$port}->{IFTYPE} == 7) {
                # WLAN network name strlen is greather than zero
                if (length((keys %{$brpsWLanName})[0]) gt 0) {
                    $device->{PORTS}->{PORT}->{$port}->{IFTYPE} = 71;
                }
            };
        }
    }
}

sub run {
    my ($self) = @_;

    my $device = $self->device
        or return;

    my %mapping = (
        SCANNED     => brScanCountCounter,
    );

    foreach my $counter (sort keys(%mapping)) {
        my $count = $self->get($mapping{$counter})
            or next;
        $device->{PAGECOUNTERS}->{$counter} = $count;
    }
    
    $self->getWlanPorts();
}

1;

__END__

=head1 NAME

GLPI::Agent::SNMP::MibSupport::BrotherNetConfig - Inventory module for Brother Printers

=head1 DESCRIPTION

The module enhances Brother printers devices support.
