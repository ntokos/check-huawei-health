#!/usr/bin/perl -w
#
# ============================== INFO ========================================
# Version	: 0.1b
# Date		: Oct 07 2024
# Author	: Christos Ntokos (University of Ioannina)
# Based on	: "check_snmp_environment" plugin (version 0.7cra) from 
#		  Charles R. Anderson
# Licence 	: GPL - summary below
#
# ============================== SUMMARY =====================================
# This plugin is based on the "check_snmp_environment" plugin (version 0.7cra)
# from Charles R. Anderson.
# This script will check the health of  huawei devices supporting the
# HUAWEI-ENTITY-EXTENT-MIB. The health checks that are supported are:
# power-supplies, fan, temperature, cpu usage, memory usage.
# The kinds of checks (mode) performed is specified via command line arguments
#
# This scrip supports IPv6. You can use the "-6" switch for this.
#
# ============================== VERSIONS ====================================
# v0.1 : Feb 05 2024
#	 - Initial version 
# v0.1a: Feb 07 2024
#	- Improve regex matching power-supply string in ENTITY-MIB
# v0.1b: Oct 07 2024
#	- Ignore slots/modules with erroneously high temperature numbers
#
# ============================== LICENCE =====================================
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# ============================== HELP ========================================
# Help: ./check_huawei_health.pl --help
# ============================================================================

use warnings;
use strict;
use Net::SNMP;
use Getopt::Long;
use lib "/usr/lib64/nagios/plugins";
use utils qw(%ERRORS $TIMEOUT);


# ============================== OID VARIABLES ===============================

# System description (for prossible future usage)
our $sysdescr				= "1.3.6.1.2.1.1.1.0";			# Global system description

# Huawei HUAWEI-ENTITY-EXTENT-MIB
our $huawei_slot_name			= "1.3.6.1.2.1.47.1.1.1.1.7";		# Component name based on Standard ENTITY-MIB
our $huawei_slot_state			= "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.2";	# Operating status of component - notSupported(1), disabled(2), enabled(3), offline(4)
our @huawei_slot_state_text		= ("","notSupported","disabled","enabled","offline");
our @huawei_slot_nagios 		= (3,2,1,0,3);
our $huawei_fan_present			= "1.3.6.1.4.1.2011.5.25.31.1.1.10.1.6";
our $huawei_fan_state			= "1.3.6.1.4.1.2011.5.25.31.1.1.10.1.7";
our @huawei_fan_state_text		= ("Absent","Normal","Abnormal");
our @huawei_fan_nagios			= (1,0,2);
our $huawei_temperature_current	= "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11";
our $huawei_temperature_thresh	= "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.12"; # Warning threshold used if thresholds are not provided
our $huawei_cpu_usage			= "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5";
our $huawei_cpu_threshold		= "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.6"; # Warning threshold used if thresholds are not provided
our $huawei_mem_usage			= "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7";
our $huawei_mem_threshold		= "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.8"; # Warning threshold used if thresholds are not provided


# ============================== GLOBAL VARIABLES ============================

our $Version		= '0.1';	# Version number of this script

our $o_host		= undef;	# Hostname
our $o_community	= undef;	# SNMP community
our $o_port		= 161;		# SNMP port
our $o_help		= undef;	# Print help text
our $o_verb		= undef;	# Verbose mode
our $o_version		= undef;	# Print version
our $o_timeout		= undef; 	# Timeout (Default 5)
our $o_perf		= undef;	# Output performance data
our $o_version1		= undef;	# Use SNMPv1
our $o_version2		= undef;	# Use SNMPv2c
our $o_domain		= undef;	# Use IPv6
our $o_check_mode	= "env";	# Default check is "env"
our @valid_modes	= (
			"cpu",
			"memory",
			"power",
			"fan",
			"temperature",
			"env",		# Environmental checks: "power", "fan", "temperature"
			"perf",		# Performance checks: "cpu", "memory"
			"all"		# ALL checks
			);
our $o_temp_warn	= undef;	# Warning temp (optional, default is value of hwEntityTemperatureThreshold oid)
our $o_temp_crit	= undef;	# Critical temp (optional, default is none)
our $o_cpu_warn		= undef;	# Warning cpu usage (optional, default is value of hwEntityCpuUsageThreshold oid)
our $o_cpu_crit		= undef;	# Critical cpu usage (optional, default is none)
our $o_login		= undef;	# Login for SNMPv3
our $o_passwd		= undef;	# Password for SNMPv3
our $v3protocols	= undef;	# V3 protocol list.
our $o_authproto	= 'sha';	# Auth protocol
our $o_privproto	= 'aes';	# Priv protocol
our $o_privpass		= undef;	# priv password



# =========================== SUBROUTINES (FUNCTIONS) ========================

# Subroutine: Print version
sub p_version { 
	print "check_huawei_health version: $Version\n"; 
}

# Subroutine: Print Usage
sub print_usage {
    print "Usage: $0 [-v] -H <host> [-6] -C <snmp_community> [-2] | (-l login -x passwd [-X pass -L <authp>,<privp>]) [-p <port>] -M (cpu|memory|power|fan|temperature|env|perf|all) [-w <prct> -c <prct>] [-a <celcius> -e <celcius>] [-f] [-t <timeout>] [-V]\n";
}

# Subroutine: Check number
sub isnnum { # Return true if arg is not a number
	my $num = shift;
	if ( $num =~ /^(\d+\.?\d*)|(^\.\d+)$/ ) { return 0 ;}
	return 1;
}

# Subroutine: Set final status
sub set_status { # Return worst status with this order : OK, unknown, warning, critical 
	my $new_status = shift;
	my $cur_status = shift;
	if ($new_status == 1 && $cur_status != 2) {$cur_status = $new_status;}
	if ($new_status == 2) {$cur_status = $new_status;}
	if ($new_status == 3 && $cur_status == 0) {$cur_status = $new_status;}
	return $cur_status;
}

# Subroutine: Check if SNMP table could be retrieved, otherwise give error
sub check_snmp_result {
	my $snmp_table		= shift;
	my $snmp_error_mesg	= shift;

	# Check if table is defined and does not contain specified error message.
	# Had to do string compare it will not work with a status code
	if (!defined($snmp_table) && $snmp_error_mesg !~ /table is empty or does not exist/) {
		printf("ERROR: ". $snmp_error_mesg . " : UNKNOWN\n");
		exit $ERRORS{"UNKNOWN"};
	}
}

# Subroutine: Print complete help
sub help {
	print "\nNagios compatible SNMP plugin for Huawei health checks\nVersion: ",$Version,"\n\n";
	print_usage();
	print <<EOT;

Options:
-v, --verbose
	Print extra debugging information 
-h, --help
	Print this help message
-H, --hostname=HOST
	Hostname or IPv4/IPv6 address of host to check
-6, --use-ipv6
	Use IPv6 connection
-C, --community=COMMUNITY NAME
	Community name for the host's SNMP agent
-1, --v1
	Use SNMPv1
-2, --v2c
	Use SNMPv2c (default)
-l, --login=LOGIN ; -x, --passwd=PASSWD
	Login and auth password for SNMPv3 authentication 
	If no priv password exists, implies AuthNoPriv 
-X, --privpass=PASSWD
	Priv password for SNMPv3 (AuthPriv protocol)
-L, --protocols=<authproto>,<privproto>
	<authproto> : Authentication protocol (md5|sha : default sha)
	<privproto> : Priv protocole (des|aes : default aes) 
-P, --port=PORT
	SNMP port (Default 161)
-M, --mode=cpu|memory|power|fan|temperature|env|perf|all  (default mode: env)
	Specifies the kinds of of health checks to run
	cpu:		CPU usage (warning/critical thresholds optional with -w, -c options)
	memory:		Memory usage (warning threshold is value of hwEntityMemUsageThreshold oid)
	power:		Power supplies state
	fan:		FAN modules state
	temperature:	Temperature values (warning/critical thresholds optional with -a, -e options)
	env:		(Default mode) Environmental status (includes power, fan, temperature)
	perf:		Performance report (includes cpu, memory)
	all:		ALL checks
-w, --cpu-warn=<percentage>
	CPU usage warning threshold (optional, default is value of hwEntityCpuUsageThreshold)
-c, --cpu-crit=<percentage>
	CPU usage critical threshold (optional, default is no threshold)
-a, --temp-warn=<celcius>
	Temperature warning threshold (optional, default is value of hwEntityTemperatureThreshold oid)
-e, --temp-crit=<celcius>
	Temperature critical threshold (optional, default is no threshold)
-f, --perfparse
	Print performance data output (for cpu, memory and temperature)
-t, --timeout=INTEGER
   Timeout for SNMP in seconds (default: 5)
-V, --version
   Prints version number

EOT
}

# Subroutine: Verbose output
sub verb { 
	my $t=shift; 
	print $t,"\n" if defined($o_verb); 
}

# Subroutine: Check command line arguments
sub check_options {
	Getopt::Long::Configure ("bundling");
	GetOptions(
	'v'	=> \$o_verb,		'verbose'	=> \$o_verb,
	'h'     => \$o_help,    	'help'        	=> \$o_help,
	'H:s'   => \$o_host,		'hostname:s'	=> \$o_host,
	'p:i'   => \$o_port,   		'port:i'	=> \$o_port,
	'C:s'   => \$o_community,	'community:s'	=> \$o_community,
	'l:s'	=> \$o_login,		'login:s'	=> \$o_login,
	'x:s'	=> \$o_passwd,		'passwd:s'	=> \$o_passwd,
	'X:s'	=> \$o_privpass,	'privpass:s'	=> \$o_privpass,
	'L:s'	=> \$v3protocols,	'protocols:s'	=> \$v3protocols,   
	't:i'   => \$o_timeout,		'timeout:i'     => \$o_timeout,
	'V'	=> \$o_version,		'version'	=> \$o_version,
	'6'     => \$o_domain,		'use-ipv6'      => \$o_domain,
	'1'     => \$o_version1,	'v1'            => \$o_version1,
	'2'     => \$o_version2,	'v2c'           => \$o_version2,
	'f'     => \$o_perf,		'perfparse'     => \$o_perf,
	'M:s'	=> \$o_check_mode,	'mode:s'	=> \$o_check_mode,
	'w:i'   => \$o_cpu_warn,	'cpu-warn:i'   	=> \$o_cpu_warn,
	'c:i'   => \$o_cpu_crit,	'cpu-crit:i'	=> \$o_cpu_crit,
	'a:i'   => \$o_temp_warn,	'temp-warn:i'	=> \$o_temp_warn,
	'e:i'   => \$o_temp_crit,	'temp-crit:i'	=> \$o_temp_crit
	);

	if (defined ($o_help) ) {
		help();
		exit $ERRORS{"UNKNOWN"};
	}

	if (defined($o_version)) { 
		p_version(); 
		exit $ERRORS{"UNKNOWN"};
	}

	# Check the -M option
	my $T_option_valid=0; 
	foreach (@valid_modes) { 
		if ($_ eq $o_check_mode) {
			$T_option_valid=1;
		} 
	}
	if ( $T_option_valid == 0 ) {
		print "Invalid check mode ",$o_check_mode," for -M option!\n"; 
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}

        # Check mode option and warning/critical thresholds consistency
        if (($o_check_mode ne "temperature" && $o_check_mode ne "env" && $o_check_mode ne "all") &&
            (defined($o_temp_warn) || defined($o_temp_crit))) {
		print "Invalid option"; 
		print " -a" if (defined($o_temp_warn));
		print " -e" if (defined($o_temp_crit));
		print " for mode ",$o_check_mode, "!\n"; 
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}
        if (($o_check_mode ne "cpu" && $o_check_mode ne "perf" && $o_check_mode ne "all") &&
            (defined($o_cpu_warn) || defined($o_cpu_crit))) {
		print "Invalid option"; 
		print " -w" if (defined($o_cpu_warn));
		print " -c" if (defined($o_cpu_crit));
		print " for mode ",$o_check_mode,"!\n"; 
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}

	# Basic checks
	if (defined($o_timeout) && (isnnum($o_timeout) || ($o_timeout < 2) || ($o_timeout > 60))) { 
		print "Timeout must be >1 and <60 !\n";
		print_usage();
		exit $ERRORS{"UNKNOWN"};
	}
	if (!defined($o_timeout)) {
		$o_timeout=5;
	}

	# check host
	if ( ! defined($o_host) ) {
		print_usage();
		exit $ERRORS{"UNKNOWN"};
	}

	# Check IPv6 
	if (defined ($o_domain)) {
		$o_domain="udp/ipv6";
	} else {
		$o_domain="udp/ipv4";
	}

	# Check SNMP information
	if ( !defined($o_community) && (!defined($o_login) || !defined($o_passwd)) ){ 
		print "Put SNMP login info!\n"; 
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}
	if ((defined($o_login) || defined($o_passwd)) && (defined($o_community) || defined($o_version2)) ){ 
		print "Can't mix SNMP v1,v2c,v3 protocols!\n"; 
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}

	# Check SNMPv3 information
	if (defined ($v3protocols)) {
		if (!defined($o_login)) { 
			print "Put SNMP V3 login info with protocols!\n"; 
			print_usage(); 
			exit $ERRORS{"UNKNOWN"};
		}
		my @v3proto=split(/,/,$v3protocols);
		if ((defined ($v3proto[0])) && ($v3proto[0] ne "")) {
			$o_authproto=$v3proto[0];
		}
		if (defined ($v3proto[1])) {
			$o_privproto=$v3proto[1];
		}
		if ((defined ($v3proto[1])) && (!defined($o_privpass))) {
			print "Put SNMP v3 priv login info with priv protocols!\n";
			print_usage(); 
			exit $ERRORS{"UNKNOWN"};
		}
	}
}


# ============================== MAIN ========================================

check_options();

# Check gobal timeout if SNMP screws up
if (defined($TIMEOUT)) {
	verb("Alarm at ".$TIMEOUT." + ".$o_timeout);
	alarm($TIMEOUT+$o_timeout);
} else {
	verb("no global timeout defined: ".$o_timeout." + 15");
	alarm ($o_timeout+15);
}

# Report when the script gets "stuck" in a loop or takes to long
$SIG{'ALRM'} = sub {
	print "UNKNOWN: Script timed out\n";
	exit $ERRORS{"UNKNOWN"};
};

# Connect to host
my ($session,$error);
if (defined($o_login) && defined($o_passwd)) {
	# SNMPv3 login
	verb("SNMPv3 login");
	if (!defined ($o_privpass)) {
		# SNMPv3 login (Without encryption)
		verb("SNMPv3 AuthNoPriv login : $o_login, $o_authproto");
		($session, $error) = Net::SNMP->session(
		-domain		=> $o_domain,
		-hostname	=> $o_host,
		-version	=> 3,
		-username	=> $o_login,
		-authpassword	=> $o_passwd,
		-authprotocol	=> $o_authproto,
		-timeout	=> $o_timeout
	);  
	} else {
		# SNMPv3 login (With encryption)
		verb("SNMPv3 AuthPriv login : $o_login, $o_authproto, $o_privproto");
		($session, $error) = Net::SNMP->session(
		-domain		=> $o_domain,
		-hostname	=> $o_host,
		-version	=> 3,
		-username	=> $o_login,
		-authpassword	=> $o_passwd,
		-authprotocol	=> $o_authproto,
		-privpassword	=> $o_privpass,
		-privprotocol	=> $o_privproto,
		-timeout	=> $o_timeout
		);
	}
} else {
	if ((defined ($o_version2)) || (!defined ($o_version1))) {
		# SNMPv2 login
		verb("SNMP v2c login");
		($session, $error) = Net::SNMP->session(
		-domain		=> $o_domain,
		-hostname	=> $o_host,
		-version	=> 2,
		-community	=> $o_community,
		-port		=> $o_port,
		-timeout	=> $o_timeout
		);
	} else {
		# SNMPv1 login
		verb("SNMP v1 login");
		($session, $error) = Net::SNMP->session(
		-domain		=> $o_domain,
		-hostname	=> $o_host,
		-version	=> 1,
		-community	=> $o_community,
		-port		=> $o_port,
		-timeout	=> $o_timeout
		);
	}
}

# Check if there are any problems with the session
if (!defined($session)) {
	printf("ERROR opening session: %s.\n", $error);
	exit $ERRORS{"UNKNOWN"};
}

my $exit_val=undef;


# ====================== Perform checks ======================================

# Define common variables for all checks
my $output		= "";
my $summ_output		= "";
my $perf_output		= "";
my $final_status	= 0;
my $nagios_status	= "OK";
my $resultat_sn		= undef;
my $slot_name		= undef;

# Define variables to track what components were found
my ($num_ps,$num_ps_ok)		= (0,0);
my ($num_fan,$num_fan_ok)	= (0,0);
my ($num_temper,$num_temper_ok)	= (0,0);
my ($num_cpu,$num_cpu_ok)	= (0,0);
my ($num_mem,$num_mem_ok)	= (0,0);


# Get component (slot) names from Standard ENTITY-MIB
# (Note: only fan check does not require component names so no need for SNMP query)
if ($o_check_mode ne "fan") {
	$resultat_sn = $session->get_table(Baseoid => $huawei_slot_name);
	&check_snmp_result($resultat_sn,$session->error);
}

# Power-supplies check (requires checking hwEntityOperStatus)
if (($o_check_mode eq "power") || ($o_check_mode eq "env") || ($o_check_mode eq "all")) {
	verb("Checking power supplies");

	my $tmp_status;
	my $ps_output	= "";
	my ($ps_status,$ps_status_text)	= (undef,undef);

	my $resultat_ss = $session->get_table(Baseoid => $huawei_slot_state);
	&check_snmp_result($resultat_ss,$session->error);

	foreach my $key ( sort keys %$resultat_sn) {
		if ($key =~ /$huawei_slot_name/) {
			# find power supply indexes based on component description
			$slot_name = $$resultat_sn{$key};

			if ($slot_name =~ /(power|pwr)( card|) [0-9]/i) {
				$num_ps++;

				$key =~ s/$huawei_slot_name//;
					
				$ps_status	= $$resultat_ss{$huawei_slot_state.$key};
				$ps_status_text = $huawei_slot_state_text[$ps_status];

				$slot_name =~ s/ /_/g;

				verb("Found PS, name: " . $slot_name . ", state: " . $ps_status_text);

				$tmp_status	= $huawei_slot_nagios[$ps_status];
				$final_status	= &set_status($tmp_status,$final_status);

				if ($tmp_status == 0) {
					$num_ps_ok++;
				}
				else {
					if ($ps_output ne "") {$ps_output.=", ";}
					$ps_output.= $slot_name . ": " . $ps_status_text;
				}
			}
		}
	}
	
	if ($ps_output ne "") {
		verb("PS not normal: " . $ps_output);
		$output .= ", " if ($output ne "");
		$output .= $ps_output;
	}
}

# Fans check
if (($o_check_mode eq "fan") || ($o_check_mode eq "env") || ($o_check_mode eq "all")) {
	verb("Checking fans");

	my $tmp_status;
	my $fan_output	= "";
	my ($fan_number,$fan_status,$fan_status_text)	= (undef,undef,undef);

	my $resultat_fp = $session->get_table(Baseoid => $huawei_fan_present);
	&check_snmp_result($resultat_fp,$session->error);
	my $resultat_fs = $session->get_table(Baseoid => $huawei_fan_state);
	&check_snmp_result($resultat_fs,$session->error);

	foreach my $key ( sort keys %$resultat_fp) {
		if ($key =~ /$huawei_fan_present/) {
			$num_fan++;
			$key =~ s/$huawei_fan_present//;	

			$fan_number = $key;
			$fan_number =~ s/\.//;
			$fan_number =~ s/\./-/g;
				
			$fan_status = $$resultat_fp{$huawei_fan_present.$key};
			if ($fan_status == 1) {
				$fan_status = $$resultat_fs{$huawei_fan_state.$key};
			}
			$fan_status_text = $huawei_fan_state_text[$fan_status];

			verb("FAN number: " . $fan_number . ", state: " . $fan_status_text);

			$tmp_status	 = $huawei_fan_nagios[$fan_status];
			$final_status 	 = &set_status($tmp_status,$final_status);

			if ($tmp_status == 0) {
				$num_fan_ok++;
			}
			else {
				if ($fan_output ne "") {$fan_output.=", ";}
				$fan_output.= "Fan " . $fan_number . ": " . $fan_status_text;
			}
		}
	}

	if ($fan_output ne "") {
		verb("FANs not normal: " . $fan_output);
		$output .= ", " if ($output ne "");
		$output .= $fan_output;
	}

}

# Temperature check
if (($o_check_mode eq "temperature") || ($o_check_mode eq "env") || ($o_check_mode eq "all")) {
	verb("Checking temperature");

	my $tmp_status;
	my $temper_output	= "";
	my $temper_status	= undef;
	my ($temper_current,$temper_thresh)	= (undef,undef);

	my $resultat_tc = $session->get_table(Baseoid => $huawei_temperature_current);
	&check_snmp_result($resultat_tc,$session->error);

	my $resultat_tth = undef;
	if (! defined($o_temp_warn)) {
		$resultat_tth = $session->get_table(Baseoid => $huawei_temperature_thresh);
		&check_snmp_result($resultat_tth,$session->error);
	}
	
	foreach my $key ( sort keys %$resultat_tc) {
		if ($key =~ /$huawei_temperature_current/) {
			# skip zero or very high temperature entries
			next if (($$resultat_tc{$key} == 0) || ($$resultat_tc{$key} > 1024));
				
			$key =~ s/$huawei_temperature_current//;
			$num_temper++;
				
			$slot_name = "";
			$slot_name = $$resultat_sn{$huawei_slot_name.$key} if (defined($resultat_sn));
			$slot_name =~ s/ /_/g;

			$temper_current = $$resultat_tc{$huawei_temperature_current.$key};
			
			verb("Sensor in: " . $slot_name . ", temperature: " . $temper_current);

			if (defined($resultat_tth)) {
				$o_temp_warn = $$resultat_tth{$huawei_temperature_thresh.$key};
			}

			$temper_status = 0;
			if (defined($o_temp_crit) && ($temper_current > $o_temp_crit)) {
				$temper_status = 2;
				$temper_thresh = $o_temp_crit;
			}
			elsif ($temper_current > $o_temp_warn) {
				$temper_status = 1;
				$temper_thresh = $o_temp_warn;
			}

			$final_status = &set_status($temper_status,$final_status);

			if ($temper_status == 0) {
				$num_temper_ok++;
			}
			else {
				if ($temper_output ne "") {$temper_output.=", ";}
				$temper_output.= "Temperature at " . $slot_name . ": " . $temper_current;
				$temper_output.= "C (over ". $temper_thresh . "C)";
			}
			
			# set performance data
			if ($perf_output ne "") {$perf_output.=", ";}
			$perf_output .= "Temp_" . $slot_name . "=" . $temper_current . ";" . $o_temp_warn;
			$perf_output .= ";" . $o_temp_crit if (defined($o_temp_crit));
		}
	}

	if ($temper_output ne "") {
		verb("TEMPER over threshold: " . $temper_output);
		$output .= ", " if ($output ne "");
		$output .= $temper_output;
	}
}

# CPU check
if (($o_check_mode eq "cpu") || ($o_check_mode eq "perf") || ($o_check_mode eq "all")) {
	verb("Checking CPU");

	my $tmp_status;
	my $cpu_output	= "";
	my $cpu_status	= undef;
	my ($cpu_current,$cpu_thresh)	= (undef,undef);

	my $resultat_cu = $session->get_table(Baseoid => $huawei_cpu_usage);
	&check_snmp_result($resultat_cu,$session->error);

	my $resultat_cth = undef;
	if (! defined($o_cpu_warn)) {
		$resultat_cth = $session->get_table(Baseoid => $huawei_cpu_threshold);
		&check_snmp_result($resultat_cth,$session->error);
	}
	
	foreach my $key ( sort keys %$resultat_cu) {
		if ($key =~ /$huawei_cpu_usage/) {
			next if ($$resultat_cu{$key} == 0);   # skip zero cpu usage entries
				
			$key =~ s/$huawei_cpu_usage//;
			$num_cpu++;
				
			$slot_name = "";
			$slot_name = $$resultat_sn{$huawei_slot_name.$key} if (defined($resultat_sn));
			$slot_name =~ s/ /_/g;

			$cpu_current = $$resultat_cu{$huawei_cpu_usage.$key};
			
			verb("CPU id: " . $slot_name . ", usage: " . $cpu_current);

			if (defined($resultat_cth)) {
				$o_cpu_warn = $$resultat_cth{$huawei_cpu_threshold.$key};
			}

			$cpu_status = 0;
			if (defined($o_cpu_crit) && ($cpu_current > $o_cpu_crit)) {
				$cpu_status = 2;
				$cpu_thresh = $o_cpu_crit;
			}
			elsif ($cpu_current > $o_cpu_warn) {
				$cpu_status = 1;
				$cpu_thresh = $o_cpu_warn;
			}

			$final_status = &set_status($cpu_status,$final_status);

			if ($cpu_status == 0) {
				$num_cpu_ok++;
			}
			else {
				if ($cpu_output ne "") {$cpu_output.=", ";}
				$cpu_output.= "CPU-usage " . $slot_name . ": " . $cpu_current;
				$cpu_output.= "% (over ". $cpu_thresh . "%)";
			}
			
			# set performance data
			if ($perf_output ne "") {$perf_output.=", ";}
			$perf_output .= "CPU_" . $slot_name . "=" . $cpu_current . ";" . $o_cpu_warn;
			$perf_output .= ";" . $o_cpu_crit if (defined($o_cpu_crit));
		}
	}

	if ($cpu_output ne "") {
		verb("CPU-usage over threshold: " . $cpu_output);
		$output .= ", " if ($output ne "");
		$output .= $cpu_output;
	}
}

# Memory check
if (($o_check_mode eq "memory") || ($o_check_mode eq "perf") || ($o_check_mode eq "all")) {
	verb("Checking Memory");

	my $tmp_status;
	my $mem_output	= "";
	my $mem_status	= undef;
	my ($mem_current,$mem_thresh)	= (undef,undef);

	my $resultat_mu = $session->get_table(Baseoid => $huawei_mem_usage);
	&check_snmp_result($resultat_mu,$session->error);

	my $resultat_mth = $session->get_table(Baseoid => $huawei_mem_threshold);
	&check_snmp_result($resultat_mth,$session->error);
	
	foreach my $key ( sort keys %$resultat_mu) {
		if ($key =~ /$huawei_mem_usage/) {
			next if ($$resultat_mu{$key} == 0);   # skip zero memory usage entries
				
			$key =~ s/$huawei_mem_usage//;
			$num_mem++;
				
			$slot_name = "";
			$slot_name = $$resultat_sn{$huawei_slot_name.$key} if (defined($resultat_sn));
			$slot_name =~ s/ /_/g;

			$mem_current = $$resultat_mu{$huawei_mem_usage.$key};
			
			verb("Memory in: " . $slot_name . ", usage: " . $mem_current);

			$mem_thresh = $$resultat_mth{$huawei_mem_threshold.$key};

			$mem_status = 0;
			if ($mem_current > $mem_thresh) {
				$mem_status = 1;
			}
			$final_status = &set_status($mem_status,$final_status);

			if ($mem_status == 0) {
				$num_mem_ok++;
			}
			else {
				if ($mem_output ne "") {$mem_output.=", ";}
				$mem_output.= "mem-usage " . $slot_name . ": ". $mem_current;
				$mem_output.= "% (over ". $mem_thresh . "%)";
			}
			
			# set performance data
			if ($perf_output ne "") {$perf_output.=", ";}
			$perf_output.= "mem_" . $slot_name . "=" . $mem_current . ";" . $mem_thresh;
		}
	}

	if ($mem_output ne "") {
		verb("Memory-usage over threshold: " . $mem_output);
		$output .= ", " if ($output ne "");
		$output .= $mem_output;
	}
}

# Clear the SNMP Transport Domain and any errors associated with the object.
$session->close;

# Check if the desired health components were found

if (($o_check_mode eq "power") && ($num_ps == 0)) {
	print "No Power-supplies found: UNKNOWN\n";
	exit $ERRORS{"UNKNOWN"};
}

if (($o_check_mode eq "fan") && ($num_fan == 0)) {
	print "No Fans found: UNKNOWN\n";
	exit $ERRORS{"UNKNOWN"};
}

if (($o_check_mode eq "temperature") && ($num_temper == 0)) {
	print "No Temperatures found: UNKNOWN\n";
	exit $ERRORS{"UNKNOWN"};
}

if (($o_check_mode eq "cpu") && ($num_cpu == 0)) {
	print "No CPU found: UNKNOWN\n";
	exit $ERRORS{"UNKNOWN"};
}

if (($o_check_mode eq "memory") && ($num_mem == 0)) {
	print "No Memory found: UNKNOWN\n";
	exit $ERRORS{"UNKNOWN"};
}

if (($o_check_mode eq "env") && ($num_ps == 0 && $num_fan == 0 && $num_temper == 0)) {
	print "No power-supplies/fans/temperature found: UNKNOWN\n";
	exit $ERRORS{"UNKNOWN"};
}

if (($o_check_mode eq "perf") && ($num_cpu == 0 && $num_mem == 0)) {
	print "No CPU/memory usage found: UNKNOWN\n";
	exit $ERRORS{"UNKNOWN"};
}

$output .=": " if ($output ne "");

if ($num_ps != 0) {
	$summ_output .= ", " if ($summ_output ne "");

	if ($num_ps == $num_ps_ok) {
	  $summ_output.= $num_ps . " power-supplies OK";
	} else {
	  $summ_output.= $num_ps_ok . "/" . $num_ps ." power-supplies OK";
	}
}

if ($num_fan != 0) {
	$summ_output .= ", " if ($summ_output ne "");

	if ($num_fan == $num_fan_ok) {
	  $summ_output.= $num_fan . " fans OK";
	} else {
	  $summ_output.= $num_fan_ok . "/" . $num_fan ." fans OK";
	}
}

if ($num_temper != 0) {
	$summ_output .= ", " if ($summ_output ne "");

	if ($num_temper == $num_temper_ok) {
	  $summ_output.= $num_temper . " temperatures OK";
	} else {
	  $summ_output.= $num_temper_ok . "/" . $num_temper ." temperatures OK";
	}
}

if ($num_cpu != 0) {
	$summ_output .= ", " if ($summ_output ne "");

	if ($num_cpu == $num_cpu_ok) {
	  $summ_output.= $num_cpu . " CPUs OK";
	} else {
	  $summ_output.= $num_cpu_ok . "/" . $num_cpu ." CPUs OK";
	}
}

if ($num_mem != 0) {
	$summ_output .= ", " if ($summ_output ne "");

	if ($num_mem == $num_mem_ok) {
	  $summ_output.= $num_mem . " Memories OK";
	} else {
	  $summ_output.= $num_mem_ok . "/" . $num_mem ." Memories OK";
	}
}

$output .= $summ_output;

if ($final_status == 3)	{ $nagios_status = "UNKNOWN"; }
elsif ($final_status == 2) { $nagios_status = "CRITICAL"; }
elsif ($final_status == 1) { $nagios_status = "WARNING"; }

$output .= " : " . $nagios_status;

if (defined($o_perf) && ($perf_output ne "")) {
	$output .= " | " . $perf_output;
}

print $output,"\n";
exit $ERRORS{$nagios_status};


# ============================== NO CHECK DEFINED ============================

print "Unknown check mode: UNKNOWN\n";
exit $ERRORS{"UNKNOWN"};


