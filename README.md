## Description
A check plugin for Nagios/Icinga to check the enviromental status (power supplies, fans and temperature) and report performance (cpu, memory) on Huawei devices.
The plugin is written in perl and uses the Net::SNMP to check Huawei devices that support the HUAWEI-ENTITY-EXTENT-MIB.
This plugin is based on the "check_snmp_environment" plugin (version 0.7cra) from Charles R. Anderson.

## Compatibility
- The plugin was written and tested for Icinga2 v.2.8 to 2.11. It probably works on Nagios/Icinga1 too.
- It has been tested in Icinga 2 for monitoring Huawei CloudEngine S5731 and S6730 series switches as well as NE-40E series routers.

## How to use
You can always run it (via command line) with the `-h` or `--help` option to see the help text.

## Disclaimer
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
