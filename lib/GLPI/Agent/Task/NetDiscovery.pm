package GLPI::Agent::Task::NetDiscovery;

use strict;
use warnings;

use parent 'GLPI::Agent::Task';

use constant DEVICE_PER_MESSAGE => 4;

use English qw(-no_match_vars);
use Time::localtime;
use Time::HiRes qw(usleep);
use UNIVERSAL::require;
use Parallel::ForkManager;
use File::Path qw(mkpath);

use GLPI::Agent::Version;
use GLPI::Agent::Tools;
use GLPI::Agent::Tools::Network;
use GLPI::Agent::Tools::Hardware;
use GLPI::Agent::Tools::Expiration;
use GLPI::Agent::Tools::SNMP;
use GLPI::Agent::HTTP::Client::OCS;
# We need to preload MibSupport configuration before running threads
use GLPI::Agent::SNMP::MibSupport;

use GLPI::Agent::Task::NetDiscovery::Version;
use GLPI::Agent::Task::NetDiscovery::Job;

our $VERSION = GLPI::Agent::Task::NetDiscovery::Version::VERSION;

sub isEnabled {
    my ($self, $contact) = @_;

    if (!$self->{target}->isType('server')) {
        $self->{logger}->debug("NetDiscovery task not compatible with local target");
        return;
    }

    if (ref($contact) ne 'GLPI::Agent::XML::Response') {
        # TODO Support NetDiscovery task via GLPI Agent Protocol
        $self->{logger}->debug("NetDiscovery task not supported by server");
        return;
    }

    my @options = $contact->getOptionsInfoByName('NETDISCOVERY');
    if (!@options) {
        $self->{logger}->debug("NetDiscovery task execution not requested");
        return;
    }

    my @jobs;
    # Parse and validate options
    foreach my $option (@options) {

        next unless ref($option) eq 'HASH';

        unless (ref($option->{RANGEIP}) eq 'ARRAY') {
            $self->{logger}->error("invalid job: no IP range defined");
            next;
        }

        my @ranges;
        foreach my $range (@{$option->{RANGEIP}}) {
            next unless ref($range) eq 'HASH';
            if (!$range->{IPSTART}) {
                $self->{logger}->error(
                    "invalid range: no first address defined"
                );
                next;
            }
            if (!$range->{IPEND}) {
                $self->{logger}->error(
                    "invalid range: no last address defined"
                );
                next;
            }
            push @ranges, $range;
        }

        if (!@ranges) {
            $self->{logger}->error("invalid job: no valid IP range defined");
            next;
        }

        unless (ref($option->{PARAM}) eq 'ARRAY') {
            $self->{logger}->error("invalid job: no valid param defined");
            next;
        }

        my $params = $option->{PARAM}->[0];

        unless (ref($params) eq 'HASH') {
            $self->{logger}->error("invalid job: no PARAM defined");
            next;
        }

        if (!defined($params->{PID})) {
            $self->{logger}->error("invalid job: no PID defined");
            next;
        }

        push @jobs, GLPI::Agent::Task::NetDiscovery::Job->new(
            logger      => $self->{logger},
            params      => $params,
            credentials => $option->{AUTHENTICATION},
            ranges      => \@ranges,
        );
    }

    if (!@jobs) {
        $self->{logger}->error("no valid job found, aborting");
        return;
    }

    $self->{jobs} = \@jobs;

    return 1;
}

sub run {
    my ($self) = @_;

    # Just reset event if run as an event to not trigger another one
    $self->resetEvent();

    my $abort = 0;
    $SIG{TERM} = sub { $abort = 1; };

    # check discovery methods available
    if (canRun('arp')) {
        $self->{arp} = 'arp -a';
    } elsif (canRun('ip')) {
        $self->{arp} = 'ip neighbor show';
    } else {
        $self->{logger}->info(
            "Can't run 'ip neighbor show' or 'arp' command, arp table detection can't be used"
        );
    }

    Net::Ping->require();
    if ($EVAL_ERROR) {
        $self->{logger}->info(
            "Can't load Net::Ping, echo ping can't be used"
        );
    }

    Net::NBName->require();
    if ($EVAL_ERROR) {
        $self->{logger}->info(
            "Can't load Net::NBName, netbios can't be used"
        );
    }

    GLPI::Agent::SNMP::Live->require();
    if ($EVAL_ERROR) {
        $self->{logger}->info(
            "Can't load GLPI::Agent::SNMP::Live, snmp detection " .
            "can't be used"
        );
    }

    # Preload MibSupport
    GLPI::Agent::SNMP::MibSupport::preload(
        config  => $self->{config},
        logger  => $self->{logger}
    );

    # Extract greatest max_threads from jobs
    my ($max_threads) = sort { $b <=> $a } map { int($_->max_threads()) }
        @{$self->{jobs}};

    # On windows, max_threads should not be upper than 60 due to a perl limitation
    if ($OSNAME eq 'MSWin32' && $max_threads > 60) {
        $self->{logger}->info("Limiting threads from $max_threads to 60 on MSWin32");
        $max_threads = 60;
    }

    # Prepare fork manager
    my $tempdir = $self->{target}->getStorage()->getDirectory();
    mkpath($tempdir);
    my $manager = Parallel::ForkManager->new($max_threads > 1 ? $max_threads : 0, $tempdir);
    $manager->set_waitpid_blocking_sleep(0);

    my %jobs = ();
    my $netscan = 0;

    # Callback to update %queues
    $manager->run_on_finish(
        sub {
            my ($pid, $ret, $jobid, $signal, $coredump, $params) = @_;
            $jobs{$jobid}->updateQueue(%{$params})
                if $jobid && $ret && $params;
        }
    );

    # Start jobs by preparing range queues and counting ips
    foreach my $job (@{$self->{jobs}}) {
        my $jobid = $job->pid;
        $jobs{$jobid} = $job;

        # We need to find if job is a netscan to compute the right expiration time
        $netscan = 1 if $job->netscan();

        $self->{logger}->debug("initializing job $jobid");

        # process each iprange
        foreach my $range ($job->ranges()) {

            $manager->start($jobid) and next;

            my ($ret, $params) = $job->getQueueParams($range);

            $manager->finish($ret, $params);
        }
    }

    $manager->wait_all_children();

    # Check computed jobs queue
    my $max_count = 0;
    my $minimum_timeout = 1;
    foreach my $job (@{$self->{jobs}}) {
        my $jobid = $job->pid;
        my $size  = $job->queuesize;
        unless ($size) {
            $self->{logger}->debug("no valid block found for job $jobid");
            # Always send control messages from a worker to avoid issue on win32
            unless ($manager->start(0)) {
                # Support glpi-netdiscovery --control option & local task from ToolBox
                $self->{_control} = $job->control;
                unless ($job->localtask) {
                    $self->_sendStartMessage($jobid);
                    $self->_sendBlockMessage($jobid, 0);
                    $self->_sendStopMessage($jobid);
                    $self->_sendStopMessage($jobid);
                }
                $manager->finish();
            }
            $manager->wait_all_children();
            delete $jobs{$jobid};
            next;
        }

        # Update total count
        $max_count += $size;

        # Update minimum expiration
        $minimum_timeout += $size * $job->timeout;
    }
    my $minimum_expiration = time + $minimum_timeout;

    # Define a realistic block scan expiration : at least one minute by address

    # Define a job expiration based on backend-collect-timeout but not less than 1 minute by device
    # Always make it larger if running a netscan
    my $target_expiration = $self->{config}->{'backend-collect-timeout'} || 60;
    $target_expiration *= 5 if $netscan;
    $target_expiration = 60 if $target_expiration < 60;
    setExpirationTime( timeout => $max_count * $target_expiration );
    my $expiration = getExpirationTime();
    $expiration = $minimum_expiration if $expiration < $minimum_expiration;
    $self->_logExpirationHours($expiration);

    # no need more worker than ips to scan
    my $worker_count = $max_threads > $max_count ? $max_count : $max_threads;
    my $queued_count = 0;

    $self->{logger}->debug("using $worker_count netdiscovery worker".($worker_count > 1 ? "s" : ""));
    $manager->set_max_procs($worker_count > 1 ? $worker_count : 0);

    my @related_job;
    my $job_count = 0;
    my $jid_len = length(sprintf("%i",$max_count));
    my $jid_pattern = "#%0".$jid_len."i, ";

    # Callback for processed scan
    $manager->run_on_finish(
        sub {
            my ($pid, $ret, $worker, $signal, $coredump, $infos) = @_;
            return unless $worker;
            my $jobid = $related_job[$worker];
            return unless $jobid;
            my $job = $jobs{$jobid};
            $queued_count--;
            if ($job->done) {
                # Support glpi-netdiscovery --control option & local task from ToolBox
                $self->{_control} = $job->control;

                # send final message to the server before cleaning jobs
                $self->_sendStopMessage($jobid) unless $job->localtask;

                delete $jobs{$jobid};

                # send final message to the server
                $self->_sendStopMessage($jobid) unless $job->localtask;
            }
            # Update expiration time if required
            if ($ret && $infos && $infos->{timeout} > 0) {
                my $expiration = getExpirationTime() + $infos->{timeout};
                setExpirationTime( expiration => $expiration );
            }
            $self->{logger}->debug(sprintf($jid_pattern, $worker)."worker termination");
        }
    );

    # We need to guaranty we don't have more than max_in_queue request in queue for each job
    while (my @jobs = sort { $a <=> $b } keys(%jobs)) {

        # Enqueue as ip as possible for each job
        foreach my $jobid (@jobs) {
            # job may has just been done & deleted in run_on_finish() manager callback
            my $job = $jobs{$jobid}
                or next;
            next unless $job->ranges;
            next if $job->max_in_queue;
            my $range = $job->range;
            my $blockip = $job->nextip()
                or next;

            $queued_count++;

            if ($expiration && time > $expiration) {
                $self->{logger}->warning("Aborting netdiscovery task as it reached expiration time");
                $self->{logger}->info("You can set backend-collect-timout higher than the default to use a longer expiration timeout");
                $abort ++;
                last;
            }

            if ($abort) {
                $self->{logger}->warning("Aborting netdiscovery task on TERM signal");
                last;
            }

            # Don't forget to send initial start message to the server
            unless ($job->started) {
                my $size = $job->queuesize;
                my $max  = $job->max_threads;
                $self->{logger}->debug("starting job $jobid with $size ip".($size > 1 ? "s" : "")." to scan using $max worker".($max > 1 ? "s" : ""));
                # Always send control messages from a worker to avoid issue on win32
                unless ($manager->start(0)) {
                    # Support glpi-netdiscovery --control option & local task from ToolBox
                    $self->{_control} = $job->control;

                    unless ($job->localtask) {
                        $self->_sendStartMessage($jobid);
                        # Also send block size to the server
                        $self->_sendBlockMessage($jobid, $size);
                    }
                    $manager->finish();
                }
                $manager->wait_all_children();
            }

            $job_count++;

            # Keep a reference to the related job for run_on_finish call
            $related_job[$job_count] = $jobid;

            # Start worker and still try to enqueue another ip for this job
            $manager->start($job_count) and redo;

            $self->{logger}->{prefix} = sprintf($jid_pattern, $job_count);

            # We should better use a new client on fork
            delete $self->{client}
                if ref($self->{client}) eq "GLPI::Agent::HTTP::Client::OCS" && $worker_count > 1;

            my $jobaddress = {
                ip                  => $blockip,
                snmp_ports          => $range->{ports},
                snmp_domains        => $range->{domains},
                entity              => $range->{entity},
                pid                 => $jobid,
                timeout             => $job->timeout,
                snmp_credentials    => $range->{snmp_credentials}   || $job->snmp_credentials,
                remote_credentials  => $range->{remote_credentials} || $job->remote_credentials
            };
            $jobaddress->{walk} = $range->{walk} if $range->{walk};

            my $result = $self->_scanAddress($jobaddress);

            if ($result && $result->{IP}) {
                $result->{ENTITY} = $range->{entity} if defined($range->{entity});

                # Keep _found private attribut from the result
                my $found = delete $result->{_found};

                my $authsnmp = $result->{AUTHSNMP};
                my $deviceid;
                # AUTHREMOTE can be set in results but is not actually supported by GLPI
                my $authremote = delete $result->{AUTHREMOTE};
                if (($authsnmp || $authremote) && $job->localtask) {
                    # Don't keep authsnmp in result for local task
                    delete $result->{AUTHSNMP};
                    # For TooBox, we keep used authsnmp|authremote & ip_range for results page in target storage
                    if ($self->{target}->isType('local')) {
                        my $device = $self->_storeNetDiscoDevices(
                            ip          => $result->{IP},
                            credential  => $authsnmp || $authremote,
                            ip_range    => $range->{name},
                            # Set expiration to ~3 months (3*30*86400)
                            expiration  => time + 7776000
                        );
                        # Still keep eventually known deviceid for later check
                        $deviceid = $device->{deviceid}
                            if defined($device->{deviceid});
                    }
                }

                # Don't send xml discovery inventory to server on computer remote inventory
                $self->_sendResultMessage($result, $jobid)
                    unless $authremote && $self->{target}->isType('server');

                # Eventually chain with netinventory when requested
                if ($job->netscan) {
                    my $timeout = 15;
                    if ($authsnmp) {
                        my $credentials = [
                            grep { $_->{ID} eq $authsnmp } @{$jobaddress->{snmp_credentials}}
                        ];

                        GLPI::Agent::Task::NetInventory->require();
                        my $inventory = GLPI::Agent::Task::NetInventory->new(
                            map { $_ => $self->{$_} } qw(config datadir target deviceid logger agentid)
                        );

                        GLPI::Agent::Task::NetInventory::Job->require();
                        $timeout = $job->timeout >= 15 ? $job->timeout : 15;
                        $inventory->{jobs} = [
                            GLPI::Agent::Task::NetInventory::Job->new(
                                params => {
                                    PID           => $jobid,
                                    THREADS_QUERY => 1,
                                    TIMEOUT       => $timeout,
                                    NO_START_STOP => 1
                                },
                                devices => [
                                    {
                                        ID          => 0,
                                        IP          => $blockip,
                                        PORT        => $result->{AUTHPORT}     // '',
                                        PROTOCOL    => $result->{AUTHPROTOCOL} // '',
                                        AUTHSNMP_ID => $authsnmp
                                    }
                                ],
                                credentials => $credentials,
                            )
                        ];

                        $inventory->{client} = $self->{client};
                        $inventory->run();

                    } elsif ($authremote) {
                        my $collectdeviceid = sub {
                            my ($inventory, $hostid) = @_;
                            # No need to update deviceid if used one if the stored one
                            return if ($hostid && ref($deviceid) eq 'HASH' && $inventory->getDeviceId() eq $deviceid->{$hostid})
                                || ($deviceid && $inventory->getDeviceId() eq $deviceid);
                            $self->_storeNetDiscoDevices(
                                ip       => $result->{IP},
                                deviceid => $inventory->getDeviceId(),
                                hostid   => $hostid
                            );
                        };
                        my $credentials = first { $_->{ID} eq $authremote } @{$jobaddress->{remote_credentials}};
                        if ($credentials && $found) {

                            # Reset timeout to backend-collect-timeout as first set one is only for discovery
                            $timeout = $self->{config}->{"backend-collect-timeout"};
                            $found->timeout($timeout);

                            my ($path, $agentfolder);
                            if ($self->{target}->isType('local')) {
                                $agentfolder = $self->{target}->getPath() eq '.' ? 'inventory' : '';
                                # When target path is agent folder, inventory should be saved in inventory subfolder
                                $path = $self->{target}->getFullPath($agentfolder);
                            }
                            # As we still have run the connection part in _scanAddressByRemote(), we reuse the connected object
                            if ($credentials->{TYPE} eq 'esx') {
                                $found->serverInventory($path, $collectdeviceid, $deviceid);
                            } else {
                                # Setup a remote inventory as it is done in GLPI::Agent::Task::RemoteInventory
                                GLPI::Agent::Task::Inventory->require();

                                # Update local target path in the case it has been updated
                                $self->{target}->setFullPath($path) if $agentfolder;

                                my $task = GLPI::Agent::Task::Inventory->new(
                                    logger      => $self->{logger},
                                    config      => $self->{config},
                                    datadir     => $self->{datadir},
                                    target      => $self->{target},
                                    agentid     => $self->{agentid},
                                    deviceid    => $found->deviceid // $found->safe_url(),
                                );

                                # Set now task is a remote one
                                $task->setRemote($found->protocol());

                                setRemoteForTools($found);

                                $task->run();

                                $found->disconnect();

                                resetRemoteForTools();
                            }
                        }
                    }

                    # Finish with return code to update task expiration
                    $manager->finish(1, { timeout => $timeout });
                }
            }

            delete $self->{logger}->{prefix} if $worker_count > 1;

            $manager->finish(0);
        }

        last if $abort;

        # wait a little bit
        usleep(50000);
        $manager->reap_finished_children();
    }

    $manager->wait_all_children();

    $self->{logger}->debug($worker_count>1 ? "All netdiscovery workers terminated" : "Netdiscovery worker terminated");

    if ($queued_count) {
        $self->{logger}->error("$queued_count devices scan result missed");
    }

    # Send exit message if we quit during a job still being run
    foreach my $jobid (sort { $a <=> $b } keys(%jobs)) {
        $self->{logger}->warning("job $jobid aborted");
        $self->_sendExitMessage($jobid) unless $jobs{$jobid}->localtask;
    }

    # Reset expiration
    setExpirationTime();
}

sub _storeNetDiscoDevices {
    my ($self, %params) = @_;

    my $storage = $self->{target}->getStorage()
        or return;

    my $ip = $params{ip}
        or return;

    my $devices = $storage->restore(name => "NetDisco-Devices") // {};
    my $hostid  = $params{hostid};
    my $updated = $devices->{$ip} ? 0 : 1;
    my $device  = $devices->{$ip} // {};

    foreach my $key (qw{credential ip_range expiration deviceid}) {
        next unless defined($params{$key});
        if ($key eq 'deviceid' && $hostid) {
            $device->{$key} = {} unless ref($device->{$key}) eq 'HASH';
            next if defined($device->{$key}->{$hostid}) && $device->{$key}->{$hostid} eq $params{$key};
            $device->{$key}->{$hostid} = $params{$key};
        } else {
            next if defined($device->{$key}) && $device->{$key} eq $params{$key};
            $device->{$key} = $params{$key};
        }
        $updated++;
    }

    $devices->{$ip} = $device;
    $storage->save(name => "NetDisco-Devices", data => $devices)
        if $updated;

    return $device;
}

sub _logExpirationHours {
    my ($self, $expiration) = @_;

    return if $self->{_remaining_next_log} && time < $self->{_remaining_next_log};

    # Turn expiration integer as a float string to compute remaining as a float
    my $remaining = ("$expiration.0" - time)/3600;

    $self->{_remaining_next_log} = time + 600;

    if ($remaining>2) {
        $remaining = sprintf("%.1f hours", $remaining);
    } elsif($remaining<1) {
        my $minutes = int($remaining*60);
        if ($minutes>=10) {
            $remaining = "$minutes minutes";
        } elsif ($minutes>1) {
            $remaining = "few minutes";
        } else {
            $remaining = "soon";
        }
    } else {
        $remaining = sprintf("%.1f hour", $remaining);
    }

    $self->{logger}->debug("Current netdiscovery run expiration timeout: $remaining");
}

sub abort {
    my ($self) = @_;

    $self->_sendStopMessage() if $self->{pid};
    $self->SUPER::abort();
}

sub _sendMessage {
    my ($self, $content) = @_;

    # Load GLPI::Agent::XML::Query as late as possible
    return unless GLPI::Agent::XML::Query->require();

    my %message_params = (
        deviceid => $self->{deviceid} || 'foo',
        query    => 'NETDISCOVERY',
        content  => $content
    );
    $message_params{tag} = $self->{config}->{'tag'}
        if defined($self->{config}->{tag}) && length($self->{config}->{tag});

    my $message = GLPI::Agent::XML::Query->new(
        %message_params
    );

    if ($self->{target}->isType('local')) {
        my ($handle, $file, $ip);
        my $path = $self->{target}->getPath();
        if ($path eq '-') {
            return unless $content->{DEVICE} || $self->{_control};
            $handle = \*STDOUT;
        } else {
            # We don't have to save control messages
            return unless $content->{DEVICE};
            $path = $self->{target}->getFullPath("netdiscovery");
            mkpath($path) unless -d $path;
            $ip = $content->{DEVICE}->[0]->{IP};
            $file = $path . "/$ip.xml";
        }

        if ($file) {
            if ($OSNAME eq 'MSWin32' && Win32::Unicode::File->require()) {
                $handle = Win32::Unicode::File->new('w', $file)
                    or $self->{logger}->error("Can't write to $file: $ERRNO");
            } else {
                open($handle, '>', $file)
                    or $self->{logger}->error("Can't write to $file: $ERRNO");
            }
            return unless $handle;
        }

        print $handle $message->getContent();

        if ($file) {
            close($handle);
            $self->{logger}->info("Netdiscovery result for $ip saved in $file");
        }

    } elsif ($self->{target}->isType('server')) {
        unless ($self->{client}) {
            $self->{client} = GLPI::Agent::HTTP::Client::OCS->new(
                logger  => $self->{logger},
                config  => $self->{config},
            );
        }

        $self->{client}->send(
            url     => $self->{target}->getUrl(),
            message => $message
        );
    }
}

sub _scanAddress {
    my ($self, $params) = @_;

    $self->{logger}->debug("scanning $params->{ip}");

    # Used by unittest to test arp cases
    $self->{arp} = $params->{arp} if $params->{arp};

    my %device;

    # First eventually try to scan with remote credentials
    if ($params->{remote_credentials}) {
        %device = $self->_scanAddressByRemote($params);
    }

    # Skip snmp scanning if got an authenticated result
    unless (!$INC{'Net/SNMP.pm'} || $device{AUTHREMOTE}) {
        %device = $self->_scanAddressBySNMP($params);
    }

    # Then scan for standard network datas
    %device = (
        $INC{'Net/NBName.pm'}    ? $self->_scanAddressByNetbios($params) : (),
        $INC{'Net/Ping.pm'}      ? $self->_scanAddressByPing($params)    : (),
        $self->{arp}             ? $self->_scanAddressByArp($params)     : (),
        %device,
    );

    # don't report anything without a minimal amount of information
    return unless
        $device{AUTHREMOTE}   ||
        $device{MAC}          ||
        $device{SNMPHOSTNAME} ||
        $device{DNSHOSTNAME}  ||
        $device{NETBIOSNAME};

    $device{IP} = $params->{ip};

    if ($device{MAC}) {
        $device{MAC} =~ tr/A-F/a-f/;
    }

    return \%device;
}

sub _scanAddressByArp {
    my ($self, $params) = @_;

    return unless $params->{ip};
    return if $params->{walk};

    # We want to match the ip including non digit character around
    my $ip_match = '\b' . $params->{ip} . '\D';
    # We want to match dot on dots
    $ip_match =~ s/\./\\./g;

    # Just to handle unittests
    my %params = ( logger => $self->{logger} );
    $params{file} = $params->{file} if $params->{file};

    my $output = getFirstMatch(
        command => $self->{arp} . " " . $params->{ip},
        pattern => qr/^(.*$ip_match.*)$/,
        %params
    );

    my %device = ();

    if ($output && $output =~ /^(\S+) \(\S+\) at (\S+) /) {
        $device{DNSHOSTNAME} = $1 if $1 ne '?';
        $device{MAC}         = getCanonicalMacAddress($2);
    } elsif ($output && $output =~ /^\s+\S+\s+([:a-zA-Z0-9-]+)\s/) {
        # Under win32, mac address separators are minus signs
        my $mac_address = $1;
        $mac_address =~ s/-/:/g;
        $device{MAC} = getCanonicalMacAddress($mac_address);
    } elsif ($output && $output =~ /^\S+\s+dev\s+\S+\s+lladdr\s+([:a-zA-Z0-9-]+)\s/) {
        $device{MAC} = getCanonicalMacAddress($1);
    }

    $self->{logger}->debug(
        sprintf "- scanning %s in arp table: %s",
        $params->{ip},
        $device{MAC} ? 'success' : 'no result'
    );

    return %device;
}

sub _scanAddressByPing {
    my ($self, $params) = @_;

    return if $params->{walk};

    my $type = 'echo';
    my $np;
    eval {
        $np = Net::Ping->new('icmp', 1);
    };

    unless ($np) {
        $self->{logger}->debug(
            sprintf "- scanning %s with $type ping: %s",
            $params->{ip},
            'no result, ping not supported'
        );
        return ();
    }

    my %device = ();

    # Avoid an error as Net::Ping::VERSION may contain underscore
    my ($NetPingVersion) = split('_',$Net::Ping::VERSION);

    if ($np->ping($params->{ip})) {
        $device{DNSHOSTNAME} = $params->{ip};
    } elsif ($NetPingVersion >= 2.67) {
        $type = 'timestamp';
        $np->message_type($type);
        if ($np->ping($params->{ip})) {
            $device{DNSHOSTNAME} = $params->{ip};
        }
    }

    $self->{logger}->debug(
        sprintf "- scanning %s with $type ping: %s",
        $params->{ip},
        $device{DNSHOSTNAME} ? 'success' : 'no result'
    );

    return %device;
}

sub _scanAddressByNetbios {
    my ($self, $params) = @_;

    return if $params->{walk};

    my $ns;
    eval {
        my $nb = Net::NBName->new();
        $ns = $nb->node_status($params->{ip});
    };

    $self->{logger}->debug(
        sprintf "- scanning %s with netbios: %s",
        $params->{ip},
        $ns ? 'success' : 'no result'
    );
    return unless $ns;

    my %device;
    foreach my $rr ($ns->names()) {
        my $suffix = $rr->suffix();
        next unless defined($suffix);
        my $G = $rr->G()
            or next;
        my $name = $rr->name()
            or next;
        if ($suffix == 0 && $G eq 'GROUP') {
            $device{WORKGROUP} = getSanitizedString($name);
        }
        if ($suffix == 3 && $G eq 'UNIQUE') {
            $device{USERSESSION} = getSanitizedString($name);
        }
        if ($suffix == 0 && $G eq 'UNIQUE') {
            $device{NETBIOSNAME} = getSanitizedString($name)
                unless $name =~ /^IS~/;
        }
    }

    my $mac = $ns->mac_address();
    if ($mac) {
        $mac =~ tr/-/:/;
        $mac = getCanonicalMacAddress($mac);
        $device{MAC} = $mac
            if $mac;
    }

    return %device;
}

sub _scanAddressBySNMP {
    my ($self, $params) = @_;

    my $tries = [];
    if ($params->{snmp_ports} && @{$params->{snmp_ports}}) {
        foreach my $port (@{$params->{snmp_ports}}) {
            my @cases = map { { port => $port, credential => $_ } } @{$params->{snmp_credentials}};
            push @{$tries}, @cases;
        }
    } else {
        @{$tries} = map { { credential => $_ } } @{$params->{snmp_credentials}};
    }
    if ($params->{snmp_domains} && @{$params->{snmp_domains}}) {
        my @domtries = ();
        foreach my $domain (@{$params->{snmp_domains}}) {
            foreach my $try (@{$tries}) {
                $try->{domain} = $domain;
            }
            push @domtries, @{$tries};
        }
        $tries = \@domtries;
    }

    foreach my $try (@{$tries}) {
        my $credential = $try->{credential};

        # Set port & domain from credential if present and not set in try for ip range
        $try->{port} = $credential->{PORT}
            if !defined($try->{port}) && defined($credential->{PORT}) && $credential->{PORT} =~ /^\d+$/;
        $try->{domain} = $credential->{PROTOCOL}
            if !defined($try->{domain}) && $credential->{PROTOCOL} && $credential->{PROTOCOL} =~ /^udp|tcp$/;

        my $device = $self->_scanAddressBySNMPReal(
            ip         => $params->{ip},
            port       => $try->{port},
            domain     => $try->{domain},
            timeout    => $params->{timeout},
            file       => $params->{walk},
            credential => $credential
        );

        # no result means either no host, no response, or invalid credentials
        $self->{logger}->debug(
            sprintf "- scanning %s%s with SNMP%s, credentials %s: %s",
            $params->{ip},
            $try->{port}   ? ':'.$try->{port}   : '',
            $try->{domain} ? ' '.$try->{domain} : '',
            $credential->{ID},
            ref $device eq 'HASH' ? 'success' :
                $device ? "no result, $device" : 'no result'
        );

        if (ref $device eq 'HASH') {
            $device->{AUTHSNMP}     = $credential->{ID};
            $device->{AUTHPORT}     = $try->{port};
            $device->{AUTHPROTOCOL} = $try->{domain};
            return %{$device};
        }
    }

    return;
}

sub _scanAddressBySNMPReal {
    my ($self, %params) = @_;

    my $snmp;
    if ($params{file}) {
        GLPI::Agent::SNMP::Mock->require();
        eval {
            $snmp = GLPI::Agent::SNMP::Mock->new(
                ip   => $params{ip},
                file => $params{file}
            );
        };
        die "SNMP emulation error: $EVAL_ERROR" if $EVAL_ERROR;
    } else {
        eval {
            # AUTHPASSPHRASE & PRIVPASSPHRASE are deprecated but still used by FusionInventory for GLPI plugin
            $snmp = GLPI::Agent::SNMP::Live->new(
                version      => $params{credential}->{VERSION},
                hostname     => $params{ip},
                port         => $params{port},
                domain       => $params{domain},
                timeout      => $params{timeout} || 1,
                community    => $params{credential}->{COMMUNITY},
                username     => $params{credential}->{USERNAME},
                authpassword => $params{credential}->{AUTHPASSPHRASE} // $params{credential}->{AUTHPASSWORD},
                authprotocol => $params{credential}->{AUTHPROTOCOL},
                privpassword => $params{credential}->{PRIVPASSPHRASE} // $params{credential}->{PRIVPASSWORD},
                privprotocol => $params{credential}->{PRIVPROTOCOL},
                retries      => $self->{config}->{'snmp-retries'} // 0,
            );
        };
    }

    # an exception here just means no device or wrong credentials
    return $EVAL_ERROR if $EVAL_ERROR;

    my $info = getDeviceInfo(
        snmp    => $snmp,
        config  => $self->{config},
        datadir => $self->{datadir},
        logger  => $self->{logger},
    );
    return unless $info;

    return $info;
}

sub _scanAddressByRemote {
    my ($self, $params) = @_;

    my (%device, $error);
    my %params = map { $_ => $self->{$_} } qw(config datadir target deviceid logger agentid);

    foreach my $credential (@{$params->{remote_credentials}}) {

        next unless $credential->{TYPE};

        if ($credential->{TYPE} eq 'esx') {

            GLPI::Agent::Task::ESX->require();

            my $esxscan = GLPI::Agent::Task::ESX->new(%params);
            $esxscan->timeout($params->{timeout});

            if ($esxscan->connect(
                host     => $params->{ip},
                user     => $credential->{USERNAME},
                password => $credential->{PASSWORD}
            )) {
                $device{_found} = $esxscan;
            } else {
                $error = $esxscan->lastError();
                my %errors = (
                    '405 Method Not Allowed' => 'not supporting VMWare SOAP API'
                );
                $error = $errors{$error} if $errors{$error};

                # Anyway set COMPUTER type if we got an answer
                $device{TYPE} = 'COMPUTER' if $error;
            }
        } else {

            GLPI::Agent::Task::RemoteInventory::Remote->require();
            URI->require();

            my $url = URI->new("http://".$params->{ip});
            my $userinfo = $credential->{USERNAME};
            $userinfo .= ":".$credential->{PASSWORD} unless empty($credential->{PASSWORD});
            $url->userinfo($userinfo) unless empty($userinfo);
            $url->port($credential->{PORT}) unless empty($credential->{PORT});
            $url->query("?mode=".$credential->{MODE}) unless empty($credential->{MODE});
            $url->scheme($credential->{TYPE});

            my $remote = GLPI::Agent::Task::RemoteInventory::Remote->new(
                config  => $self->{config},
                logger  => $self->{logger},
                url     => $url->as_string(),
                timeout => $params->{timeout},
            );
            next unless $remote->supported();

            $remote->prepare();

            $error = $remote->checking_error();
            $device{_found} = $remote
                unless $error;
        }

        # no result means either no host, no response, or invalid credentials
        $self->{logger}->debug(
            sprintf "- scanning %s%s with %s, credentials %s: %s",
            $params->{ip},
            $credential->{TYPE} ne 'esx' && $credential->{PORT} ? ':'.$credential->{PORT} : '',
            $credential->{TYPE} eq 'esx' ? 'ESX' : $credential->{TYPE}.' RemoteInventory',
            $credential->{ID},
            $device{_found} ? 'success' : $error ? "no result, $error"  : 'no result'
        );

        if ($device{_found}) {
            $device{AUTHREMOTE} = $credential->{ID};
            $device{TYPE}       = 'COMPUTER';
            last;
        }

        undef $error;
    }

    return %device;
}

sub _sendStartMessage {
    my ($self, $pid) = @_;

    $self->_sendMessage({
        AGENT => {
            START        => 1,
            AGENTVERSION => $GLPI::Agent::Version::VERSION,
        },
        MODULEVERSION => $VERSION,
        PROCESSNUMBER => $pid
    });
}

sub _sendStopMessage {
    my ($self, $pid) = @_;

    $self->_sendMessage({
        AGENT => {
            END => 1,
        },
        MODULEVERSION => $VERSION,
        PROCESSNUMBER => $pid
    });
}

sub _sendExitMessage {
    my ($self, $pid) = @_;

    $self->_sendMessage({
        AGENT => {
            EXIT => 1,
        },
        MODULEVERSION => $VERSION,
        PROCESSNUMBER => $pid
    });
}

sub _sendBlockMessage {
    my ($self, $pid, $count) = @_;

    $self->_sendMessage({
        AGENT => {
            NBIP => $count
        },
        PROCESSNUMBER => $pid
    });
}

sub _sendResultMessage {
    my ($self, $result, $pid) = @_;

    $self->_sendMessage({
        DEVICE        => [$result],
        MODULEVERSION => $VERSION,
        PROCESSNUMBER => $pid
    });
}

1;

__END__

=head1 NAME

GLPI::Agent::Task::NetDiscovery - Net discovery support for GLPI Agent

=head1 DESCRIPTION

This tasks scans the network to find connected devices, allowing:

=over

=item *

devices discovery within an IP range, through arp, ping, NetBios or SNMP

=item *

devices identification, through SNMP

=back

This task requires a GLPI server with a FusionInventory compatible plugin.
