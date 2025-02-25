#!/usr/bin/perl

use strict;
use warnings;
use lib 't/lib';

use UNIVERSAL::require;

use Test::Deep;
use Test::Exception;
use Test::More;
use Test::NoWarnings;

use GLPI::Test::Inventory;
use GLPI::Agent::Task::Inventory::MacOS::AntiVirus;

my %av_tests = (
    'defender-101.98.30' => {
        _module         => "Defender",
        _funcion        => "_getMSDefender",
        COMPANY         => "Microsoft",
        NAME            => "Microsoft Defender",
        ENABLED         => 1,
        UPTODATE        => 1,
        VERSION         => "101.98.30",
        BASE_VERSION    => "1.389.10.0",
        EXPIRATION      => "2023-09-06",
        BASE_CREATION   => "2023-05-03",
    },
    'cortex-xdr-8.2.1.47908' => {
        _module         => "Cortex",
        _funcion        => "_getCortex",
        COMPANY         => "Palo Alto Networks",
        NAME            => "Cortex XDR",
        ENABLED         => 1,
        VERSION         => "8.2.1.47908",
        BASE_VERSION    => "1270-79108",
    },
    'sentinelone-epp-24.1.2.7444' => {
        _module         => "SentinelOne",
        _funcion        => "_getSentinelOne",
        COMPANY         => "Sentinel Labs Inc.",
        NAME            => "SentinelOne EPP",
        ENABLED         => 1,
        VERSION         => "24.1.2.7444",
    },
);

plan tests =>
    (2 * scalar keys %av_tests) +
    1;

my $inventory = GLPI::Test::Inventory->new();

foreach my $test (sort keys %av_tests) {
    my $module = "GLPI::Agent::Task::Inventory::MacOS::AntiVirus::".(delete $av_tests{$test}->{_module});
    $module->require();
    my $funct_name = $module."::".(delete $av_tests{$test}->{_funcion});
    my $function = \&{$funct_name};
    my $basefile = "resources/macos/antivirus/$test";
    my $antivirus = &{$function}(basefile => $basefile);
    cmp_deeply($antivirus, $av_tests{$test}, "$test: parsing");
    lives_ok {
        $inventory->addEntry(section => 'ANTIVIRUS', entry => $antivirus);
    } "$test: registering";
}
