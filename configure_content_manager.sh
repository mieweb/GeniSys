#!/bin/bash
echo "Welcome to the MIE Testing Content Manger setup."
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi
echo "Installing necessary tools"
apt update && sudo apt upgrade
apt-get install dnsmasq
apt-get install iptables
apt-get install iptables-persistent
apt-get install vsftpd`
echo "Detecting network interfaces..."
correct='n'
until [[ $correct == 'y' ]]
do
    declare -A interfaceIP
    declare -A selectInterface
    interfaces=$(ip -o link show | awk -F': ' '{print $2}')
    red_interface=""
    green_interface=""
    dhcp_configured=""
    selector=1
    echo "Available Interfaces:"
    for iface in $interfaces; do
        if [[ $iface != "lo" ]]; then
            if [[ -n $(ip -o addr show $iface | grep -v inet6 | awk '{print $4}') ]]; then
                interfaceIP["$iface"]=$(ip -o addr show $iface | grep -v inet6 | awk '{print $4}')
                selectInterface["$selector"]=$iface
                if [[ -n $(cat /var/lib/dhcp/dhclient.leases | grep $iface 2>/dev/null) ]]; then
                    dhcp_configured="true"
                    echo "    ${selector}. Interface $iface is up and has IP address: ${interfaceIP[$iface]}. - DHCP configured on $iface."
                else
                    echo "    ${selector}. Interface $iface is up and has IP address: ${interfaceIP[$iface]}. - No DHCP configured on $iface."
                fi
            else
                interfaceIP["$iface"]="0.0.0.0"
                echo "${selector}. Interface $iface is not up and has no IP address."
            fi
            (( selector++ ))
        fi
    done
    (( selector-- ))
    read -p "Select (1-$selector) RED interface: " red_interface
    read -p "Select (1-$selector) GREEN interface: " green_interface
    echo "Selected Interfaces:"
    echo "    RED - ${selectInterface[$red_interface]} - ${interfaceIP[${selectInterface[$red_interface]}]}"
    echo "    GREEN - ${selectInterface[$green_interface]} - ${interfaceIP[${selectInterface[$green_interface]}]}"
    read -p "Is this correct y/n?" correct
done
correct='n'
while [[ $correct == 'y' ]]
do
    read -p "DHCP Range start: " dhcpStart
    read -p "DHCP Range end: " dhcpEnd
    read -p "CIDR mask: " cidrmask
    read -p "Lease length(in hours): " lease
    echo "DHCP start: ${dhcpStart} | end: ${dhcpEnd} | CIDR: ${cidrmask} | lease: ${lease}h"
    read -p "Is this correct y/n?" correct
done
netmask=$(printf "%d.%d.%d.%d\n" $(( 0xFFFFFFFF << (32 - $cidr) & 0xFF )) $(( 0xFFFFFFFF << (32 - $cidr) >> 8 & 0xFF )) $(( 0xFFFFFFFF << (32 - $cidr) >> 16 & 0xFF )) $(( 0xFFFFFFFF << (32 - $cidr) >> 24 & 0xFF )))
echo "Calculated netmask: ${netmask}"
echo "Writing config files dnsmasq.conf"
cat <<EOF > /etc/dnsmasq.conf
user=$(whoami)
group=$(id -g -n)
interface=${selectInterface[$green_interface]}
dhcp-range=$dhcpEnd,$dhcpStart,$netmask,$lease
dhcp-boot=pxelinux.0,pxeserver
pxe-prompt="Network Booting", 10
pxe-service=X86PC, "MIE PXELINUX", "pxelinux.0"
enable-tftp
tftp-root=/var/ftpd
tftp-no-fail
tftp-secure
tftp-no-blocksize
log-queries
log-dhcp
EOF
echo "Writing FTP confs"
cat <<EOF > /etc/vsftpd.conf
listen=NO
listen_ipv6=YES
anonymous_enable=YES
local_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_std_format=YES
log_ftp_protocol=YES
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
local_root=/var/ftpd
EOF
echo "Fixing DNS for GREEN interface"
cat << EOF > /etc/systemd/system/dhclient_cm.service
[Unit]
Description=DHCP client for ${selectInterface[$red_interface]}
After=network.target

[Service]
Type=simple
ExecStart=/sbin/dhclient -v ${selectInterface[$red_interface]}

[Install]
WantedBy=multi-user.target
EOF
echo "Setting up packet forwarding"
if grep -q '^net\.ipv4\.ip_forward=' /etc/sysctl.conf; then
    sed -i "s/^net\.ipv4\.ip_forward=.*/net.ipv4.ip_forward=$new_value/" /etc/sysctl.conf
else
    echo "net.ipv4.ip_forward=$new_value" >> /etc/sysctl.conf
fi
echo "Fetching Debian image"
wget https://ftp.debian.org/debian/dists/bullseye/main/installer-amd64/current/images/netboot/netboot.tar.gz -P /var/ftpd/
tar -xzvf /var/ftpd/netboot.tar.gz
rm /var/ftpd/netboot.tar.gz
ln -s debian-installer/amd64/grubx64.efi .
ln -s debian-installer/amd64/grub .
echo "Writing preseed.cfg"
cat <<EOF > /var/ftpd/preseed.cfg
### Localization
d-i debian-installer/locale string en_US
d-i keyboard-configuration/xkb-keymap select us
### Network configuration
d-i netcfg/choose_interface select auto
### Hostname
#d-i preseed/early_command string \
    # Generate a random hostname
    #RANDOM_HOSTNAME=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 10 | head -n 1); \
    #echo "d-i netcfg/get_hostname string ${RANDOM_HOSTNAME}-proxmox" | debconf-set-selections; \
    #echo "d-i netcfg/hostname string ${RANDOM_HOSTNAME}-proxmox" | debconf-set-selections
d-i netcfg/get_hostname string unassigned-hostname
d-i netcfg/get_domain string unassigned-domain
d-i netcfg/get_hostname seen true
d-i netcfg/get_domain seen true
### Mirror settings
d-i mirror/country string manual
d-i mirror/http/hostname string ftp.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string
### Partitioning
d-i partman-auto/method string regular
d-i partman-auto/purge_lvm_from_device boolean true
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman-auto-lvm/guided_size string max
d-i partman-auto/choose_recipe select atomic
d-i partman/default_filesystem string ext4
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
### Account setup
d-i passwd/root-login boolean true
d-i passwd/root-password-crypted password $6$g4eD5Gg66EOLnpkS$305TXiEcMGmi7et4WEX/RvvSNp/05sWX5CR4UsU1BUXcpLGYqBh2CCMn3xpHyD.ILLjLCKiMiK5To3MLrO92i/
d-i passwd/make-user boolean true
d-i passwd/user-fullname string Admin User
d-i passwd/username string mietest
d-i passwd/user-password-crypted password $6$g4eD5Gg66EOLnpkS$305TXiEcMGmi7et4WEX/RvvSNp/05sWX5CR4UsU1BUXcpLGYqBh2CCMn3xpHyD.ILLjLCKiMiK5To3MLrO92i/
### Grub boot loader installation
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/sda
### Finish installation
d-i finish-install/reboot_in_progress note
### Package selection
tasksel tasksel/first multiselect standard
d-i pkgsel/include string openssh-server
### Apt configuration
d-i apt-setup/non-free boolean true
d-i apt-setup/contrib boolean true
### Language packs
d-i pkgsel/language-packs multiselect en
### Timezone
d-i time/zone string America/New_York
### Clock and NTP
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true
### Popularity contest
popularity-contest popularity-contest/participate boolean false
d-i preseed/late_command string \
    in-target wget -O /tmp/deb-to-proxmox.sh ftp://${interfaceIP[${selectInterface[$green_interface]}]}/deb-to-proxmox.sh; \
    in-target wget -O /tmp/deb-to-proxmox.service ftp://${interfaceIP[${selectInterface[$green_interface]}]}/deb-to-proxmox.service; \
    in-target chmod +x /tmp/deb-to-proxmox.sh; \
    in-target chmod +x /tmp/deb-to-proxmox.service; \
    in-target cp /tmp/deb-to-proxmox.sh /usr/local/bin/; \
    in-target cp /tmp/deb-to-proxmox.service /etc/systemd/system/; \
    in-target systemctl enable deb-to-proxmox.service
EOF
echo "Writing PXE Scripts"
cat <<EOF > /var/ftpd/deb-to-proxmox.service
[Unit]
Description=Script to run deb-to-proxmox.sh
After=network.target
Wants=network.target
[Service]
ExecStart=/usr/local/bin/deb-to-proxmox.sh
[Install]
WantedBy=multi-user.target
EOF

cat <<END > /var/ftpd/deb-to-proxmox.sh
#!/usr/bin/env bash
################################################################################
# This is property of eXtremeSHOK.com
# You are free to use, modify and distribute, however you may not remove this notice.
# Copyright (c) Adrian Jon Kriel :: admin@extremeshok.com
################################################################################
#
# Script updates can be found at: https://github.com/extremeshok/xshok-proxmox
#
# Debian 11 to Proxmox 7 conversion script
#
# License: BSD (Berkeley Software Distribution)
#
################################################################################
#
# Assumptions: Debian10 installed with a valid FQDN hostname set
#
# Tested on KVM, VirtualBox and Dedicated Server
#
# Will automatically detect cloud-init and disable.
# Will automatically generate a correct /etc/hosts
#
# Note: will automatically run the install-post.sh script
#
# Thank you @floco
#
#
# Modified exclusively for Medical Informatics Engineering Internal testing By Jedidiah Chance jchance@mieweb.com
#
#
echo "Starting deb-to-proxmox"
# Generate random hostname
#random_string=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1 | awk '{print "proxmox-"$0}')
#echo "Random string: $random_string"
# Set the generated random string as the hostname
#hostnamectl set-hostname "$random_string"
# Update the /etc/hosts file with the new hostname
#sed -i "s/127.0.1.1.*/127.0.1.1\t$random_string/g" /etc/hosts
#systemctl restart networking.service
#echo "New hostname: $random_hostname"

# Set the local
export LANG="en_US.UTF-8"
export LC_ALL="C"
sh -c "echo -e 'LANG=en_US.UTF-8\nLC_ALL=en_US.UTF-8' > /etc/default/locale"

#create lock dir for aptitude
if [ -d "/run/lock" ] ; then
  mkdir /run/lock
  chmod a+rwxt /run/lock
fi

echo "Deinstalling any linux firmware packages "
firmware="$(dpkg -l | grep -i 'firmware-')"
if [ -n "$firmware" ]; then
  /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' purge firmware-bnx2x firmware-realtek firmware-linux firmware-linux-free firmware-linux-nonfree
else
  echo "No firmware packages loaded"
fi

echo "Deinstalling the Debian standard kernel packages "
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' purge linux-image-amd64

echo "Removing conflicting packages"
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' purge os-prober
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' autoremove
apt-get clean all

echo "Auto detecting existing network settings"
default_interface="$(ip route | awk '/default/ { print $5 }' | grep -v "vmbr")"
if [ "$default_interface" == "" ]; then
  #filter the interfaces to get the default interface and which is not down and not a virtual bridge
  default_interface="$(ip link | sed -e '/state DOWN / { N; d; }' | sed -e '/veth[0-9].*:/ { N; d; }' | sed -e '/vmbr[0-9].*:/ { N; d; }' | sed -e '/tap[0-9].*:/ { N; d; }' | sed -e '/lo:/ { N; d; }' | head -n 1 | cut -d':' -f 2 | xargs)"
fi
if [ "$default_interface" == "" ]; then
  echo "ERROR: Could not detect default interface"
  exit 1
fi
loopcount=0
while [[ $loopcount -lt 10  ]] && ! ip -4 addr show dev "$default_interface" | grep -q "inet "; do
    sleep 6
    ((loopcount++))
done
default_v4="$(ip -4 addr show dev "$default_interface" | awk '/inet/ { print $2 }' )"
default_v4ip=${default_v4%/*}
if [ "$default_v4ip" == "" ] ; then
  echo "ERROR: Could not detect default IPv4 address"
  echo "IP: ${default_v4ip}"
  exit 1
fi
echo "GENERATING HOSTNAME"
# Generate random hostname
random_string=$(openssl rand 2048 | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1 | awk '{print "proxmox-"$0}')
echo "Random string: $random_string"
# Set the generated random string as the hostname
hostnamectl set-hostname "$random_string"
# Update the /etc/hosts file with the new hostname
#systemctl restart networking.service
echo "New hostname: $random_hostname"

echo "Configure /etc/hosts"
if [ -f /etc/cloud/cloud.cfg ] ; then
  echo 'manage_etc_hosts: False' | tee --append /etc/cloud/cloud.cfg
fi
sed -i "s/^ - update_etc_hosts/# - update_etc_hosts/" /etc/cloud/cloud.cfg
cat <<EOF > /etc/hosts
127.0.0.1 localhost.localdomain localhost
${default_v4ip} $(hostname -f) $(hostname -s) pvelocalhost
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
EOF

echo "Add Proxmox repo to APT sources"
cat <<EOF >> /etc/apt/sources.list.d/proxmox.list
# PVE packages provided by proxmox.com"
deb [arch=amd64] http://download.proxmox.com/debian/pve bullseye pve-no-subscription
EOF
wget -q "https://enterprise.proxmox.com/debian/proxmox-release-bullseye.gpg" -O /etc/apt/trusted.gpg.d/proxmox-release-bullseye.gpg
apt-get update > /dev/null

echo "Upgrading system"
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' full-upgrade

echo "Installing postfix"
cat <<EOF | debconf-set-selections
postfix postfix/mailname           string $(cat /etc/hostname)
postfix postfix/destinations       string $(cat /etc/hostname), proxmox, localhost.localdomain, localhost
postfix postfix/chattr             boolean false
postfix postfix/mailbox_limit      string 0
postfix postfix/main_mailer_type   select Local only
postfix postfix/mynetworks         string 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
postfix postfix/protocols          select all
postfix postfix/recipient_delim    string +
postfix postfix/rfc1035_violation  boolean false
EOF
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' install -y postfix

echo "Installing open-iscsi"
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' install -y open-iscsi

echo "Installing proxmox-ve"
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' install -y proxmox-ve

echo "Remove legacy (5.10) kernel"
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' remove linux-image-amd64 linux-image-5.10*

echo "Force grub to update"
update-grub

echo "Remove os=prober"
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' remove os-prober

echo "Remove enterprise repo"
rm -f /etc/apt/sources.list.d/pve-install-repo.list

echo "Done installing Proxmox VE"

echo "Creating admin user"
pveum groupadd admin -comment "System Administrators"
pveum aclmod / -group admin -role Administrator
pveum useradd admin@pve -comment "Admin"
pveum usermod admin@pve -group admin

OS_CODENAME="$(grep "VERSION_CODENAME=" /etc/os-release | cut -d"=" -f 2 | xargs )"

if [ -f /etc/apt/sources.list.d/pve-enterprise.list ]; then
  sed -i "s/^deb/#deb/g" /etc/apt/sources.list.d/pve-enterprise.list
fi
# enable free public proxmox repo
if [ ! -f /etc/apt/sources.list.d/proxmox.list ] && [ ! -f /etc/apt/sources.list.d/pve-public-repo.list ] && [ ! -f /etc/apt/sources.list.d/pve-install-repo.list ] ; then
  echo -e "deb http://download.proxmox.com/debian/pve ${OS_CODENAME} pve-no-subscription\\n" > /etc/apt/sources.list.d/pve-public-repo.list
fi
cat <<EOF > /etc/apt/sources.list
deb https://ftp.debian.org/debian ${OS_CODENAME} main contrib
deb https://ftp.debian.org/debian ${OS_CODENAME}-updates main contrib
# non-free
deb https://httpredir.debian.org/debian/ ${OS_CODENAME} main contrib non-free
# security updates
deb https://security.debian.org/debian-security ${OS_CODENAME}/updates main contrib
EOF

# Refresh the package lists
apt-get update > /dev/null 2>&1

# Remove conflicting utilities
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' purge ntp openntpd systemd-timesyncd

# Fixes for common apt repo errors
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' install apt-transport-https debian-archive-keyring ca-certificates curl
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' dist-upgrade
pveam update
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' install zfsutils-linux proxmox-backup-restore-image chrony
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' install \
   axel \
   build-essential \
   curl \
   dialog \
   dnsutils \
   dos2unix \
   git \
   gnupg-agent \
   grc \
   htop \
   iftop \
   iotop \
   iperf \
   ipset \
   iptraf \
   mlocate \
   msr-tools \
   nano \
   net-tools \
   omping \
   software-properties-common \
   sshpass \
   tmux \
   unzip \
   vim \
   vim-nox \
   wget \
   whois \
   zip
# Add the latest ceph provided by proxmox
echo "deb http://download.proxmox.com/debian/ceph-pacific ${OS_CODENAME} main" > /etc/apt/sources.list.d/ceph-pacific.list
## Refresh the package lists
apt-get update > /dev/null 2>&1
## Install ceph support
echo "Y" | pveceph install
# Fail2Ban
## Protect the web interface with fail2ban
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' install fail2ban

cat <<EOF > /etc/fail2ban/filter.d/proxmox.conf
[Definition]
failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*
ignoreregex =
EOF

cat <<EOF > /etc/fail2ban/jail.d/proxmox.conf
[proxmox]
enabled = true
port = https,http,8006,8007
filter = proxmox
logpath = /var/log/daemon.log
maxretry = 3
# 1 hour
bantime = 3600
findtime = 600
EOF

systemctl enable fail2ban

if [ -f "/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js" ] ; then
      # create a daily cron to make sure the banner does not re-appear
cat <<'EOF' > /etc/cron.daily/xs-pve-nosub
#!/bin/sh
# Remove subscription banner
sed -i "s/data.status !== 'Active'/false/g" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js
sed -i "s/checked_command: function(orig_cmd) {/checked_command: function() {} || function(orig_cmd) {/g" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js
EOF
  chmod 755 /etc/cron.daily/xs-pve-nosub
  bash /etc/cron.daily/xs-pve-nosub
fi
    # Remove nag @tinof
echo "DPkg::Post-Invoke { \"dpkg -V proxmox-widget-toolkit | grep -q '/proxmoxlib\.js$'; if [ \$? -eq 1 ]; then { echo 'Removing subscription nag from UI...'; sed -i '/data.status/{s/\!//;s/Active/NoMoreNagging/}' /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js; }; fi\"; };" > /etc/apt/apt.conf.d/xs-pve-no-nag && apt --reinstall install proxmox-widget-toolkit

 cat <<EOF > /etc/sysctl.d/99-xs-kernelpanic.conf
# Enable restart on kernel panic, kernel oops and hardlockup
kernel.core_pattern=/var/crash/core.%t.%p
# Reboot on kernel panic afetr 10s
kernel.panic=10
# Panic on kernel oops, kernel exploits generally create an oops
kernel.panic_on_oops=1
# Panic on a hardlockup
kernel.hardlockup_panic=1
EOF

cat <<EOF > /etc/logrotate.conf
daily
su root adm
rotate 7
create
compress
size=10M
delaycompress
copytruncate
include /etc/logrotate.d
EOF
systemctl restart logrotate
cat <<EOF > /etc/systemd/journald.conf
[Journal]
# Store on disk
Storage=persistent
# Don't split Journald logs by user
SplitMode=none
# Disable rate limits
RateLimitInterval=0
RateLimitIntervalSec=0
RateLimitBurst=0
# Disable Journald forwarding to syslog
ForwardToSyslog=no
# Journald forwarding to wall /var/log/kern.log
ForwardToWall=yes
# Disable signing of the logs, save cpu resources.
Seal=no
Compress=yes
# Fix the log size
SystemMaxUse=64M
RuntimeMaxUse=60M
# Optimise the logging and speed up tasks
MaxLevelStore=warning
MaxLevelSyslog=warning
MaxLevelKMsg=warning
MaxLevelConsole=notice
MaxLevelWall=crit
EOF
systemctl restart systemd-journald.service
journalctl --vacuum-size=64M --vacuum-time=1d;
journalctl --rotate
## Increase vzdump backup speed
sed -i "s/#bwlimit:.*/bwlimit: 0/" /etc/vzdump.conf
sed -i "s/#ionice:.*/ionice: 5/" /etc/vzdump.conf
## Optimise Memory
cat <<EOF > /etc/sysctl.d/99-xs-memory.conf
# Memory Optimising
## Bugfix: reserve 1024MB memory for system
vm.min_free_kbytes=1048576
vm.nr_hugepages=72
# (Redis/MongoDB)
vm.max_map_count=262144
vm.overcommit_memory = 1
EOF
## Enable TCP fastopen
cat <<EOF > /etc/sysctl.d/99-xs-tcp-fastopen.conf
# TCP fastopen
net.ipv4.tcp_fastopen=3
EOF
## Enable Network optimising
cat <<EOF > /etc/sysctl.d/99-xs-net.conf
net.core.netdev_max_backlog=8192
net.core.optmem_max=8192
net.core.rmem_max=16777216
net.core.somaxconn=8151
net.core.wmem_max=16777216
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_challenge_ack_limit = 999999999
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_keepalive_time=240
net.ipv4.tcp_limit_output_bytes=65536
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_rmem=8192 87380 16777216
net.ipv4.tcp_sack=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_wmem=8192 65536 16777216
net.netfilter.nf_conntrack_generic_timeout = 60
net.netfilter.nf_conntrack_helper=0
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 28800
net.unix.max_dgram_qlen = 4096
EOF
## Bugfix: high swap usage with low memory usage
cat <<EOF > /etc/sysctl.d/99-xs-swap.conf
# Bugfix: high swap usage with low memory usage
vm.swappiness=10
EOF
## Increase Max FS open files
cat <<EOF > /etc/sysctl.d/99-xs-fs.conf
# Max FS Optimising
fs.nr_open=12000000
fs.file-max=9000000
fs.aio-max-nr=524288
EOF

## Optimise ZFS arc size accoring to memory size
if [ "$(command -v zfs)" != "" ] ; then
  if [[ RAM_SIZE_GB -le 16 ]] ; then
    MY_ZFS_ARC_MIN=536870911
    MY_ZFS_ARC_MAX=536870912
elif [[ RAM_SIZE_GB -le 32 ]] ; then
    # 1GB/1GB
    MY_ZFS_ARC_MIN=1073741823
    MY_ZFS_ARC_MAX=1073741824
  else
    MY_ZFS_ARC_MIN=$((RAM_SIZE_GB * 1073741824 / 16))
    MY_ZFS_ARC_MAX=$((RAM_SIZE_GB * 1073741824 / 8))
  fi
  # Enforce the minimum, incase of a faulty vmstat
  if [[ MY_ZFS_ARC_MIN -lt 536870911 ]] ; then
    MY_ZFS_ARC_MIN=536870911
  fi
  if [[ MY_ZFS_ARC_MAX -lt 536870912 ]] ; then
    MY_ZFS_ARC_MAX=536870912
  fi
  cat <<EOF > /etc/modprobe.d/99-xs-zfsarc.conf
# Use 1/8 RAM for MAX cache, 1/16 RAM for MIN cache, or 1GB
options zfs zfs_arc_min=$MY_ZFS_ARC_MIN
options zfs zfs_arc_max=$MY_ZFS_ARC_MAX

# use the prefetch method
options zfs l2arc_noprefetch=0

# max write speed to l2arc
# tradeoff between write/read and durability of ssd (?)
# default : 8 * 1024 * 1024
# setting here : 500 * 1024 * 1024
options zfs l2arc_write_max=524288000
options zfs zfs_txg_timeout=60
EOF
fi
# Fix missing /etc/network/interfaces.d include
if ! grep -q 'source /etc/network/interfaces.d/*' "/etc/network/interfaces" ; then
    echo "Added missing include to /etc/network/interfaces"
    echo "source /etc/network/interfaces.d/*" >> /etc/network/interfaces
fi

# Enable IOMMU
cpu=$(cat /proc/cpuinfo)
if [[ $cpu == *"GenuineIntel"* ]]; then
    echo "Detected Intel CPU"
    sed -i 's/quiet/quiet intel_iommu=on iommu=pt/g' /etc/default/grub
elif [[ $cpu == *"AuthenticAMD"* ]]; then
    echo "Detected AMD CPU"
    sed -i 's/quiet/quiet amd_iommu=on iommu=pt/g' /etc/default/grub
else
    echo "Unknown CPU"
fi
cat <<EOF >> /etc/modules
vfio
vfio_iommu_type1
vfio_pci
vfio_virqfd

EOF
cat <<EOF >> /etc/modprobe.d/blacklist.conf
blacklist nouveau
blacklist lbm-nouveau
options nouveau modeset=0
blacklist amdgpu
blacklist radeon
blacklist nvidia
blacklist nvidiafb
EOF

# propagate the settings
update-initramfs -u -k all
update-grub
pve-efiboot-tool refresh

# cleanup
## Remove no longer required packages and purge old cached updates
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' autoremove
/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' autoclean

echo "Setting admin user password"
yes "P@ssw00rd" | pveum passwd admin@pve 

network=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | awk -F/ '{print $1}' | awk -F. '{print $1"."$2"."$3}')
currentip=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | awk -F/ '{print $1}' | awk -F. '{print $1"."$2"."$3"."$4}')

# Define the range of IP addresses to check
start_ip=1
end_ip=254

# Loop through the IP addresses in the range
for ((ip=$start_ip; ip<=$end_ip; ip++)); do
  ip_address="$network.$ip"
  if [[ "$ip_address" != "$currentip" ]]; then
    # Use curl to make a request to port 8006 and extract the Server header
    echo "Checking $ip_address..."
    server_header=$(curl -s -I --max-time 1 "$ip_address:8006" | grep -i "^Server:" | awk '{print $2}')
    # Check if the Server header contains "pve-api-daemon"
    if [[ "$server_header" == *"pve-api-daemon"* ]]; then
      yes $'P@ssw00rd\nYes' | pvecm add "$ip_address"
      exit
    fi
  fi
done

pvecm create testcluster
systemctl stop deb-to-proxmox.service
systemctl disable deb-to-proxmox.service
rm /usr/local/bin/deb-to-proxmox.sh
rm /etc/systemd/system/deb-to-proxmox.service
systemctl daemon-reload
systemctl reset-failed
END
cat <<EOF > /etc/netplan/01-netcfg.yaml
network:
  ethernets:
    ${selectInterface[$green_interface]}:
      dhcp4: false
      addresses: [${interfaceIP[${selectInterface[$red_interface]}]}${cidrmask}]
    ${selectInterface[$red_interface]}:
      dhcp4: true
  version: 2
EOF
base_address=$(IFS=. read -r i1 i2 i3 i4 <<< "$interfaceIP[${selectInterface[$red_interface]}]"; IFS=. read -r m1 m2 m3 m4 <<< $(printf "%d.%d.%d.%d\n" "$((0xffffffff << (32 - $cidrmask)) & 0xff000000 >> 24)" "$((0xffffffff << (32 - $cidrmask)) & 0x00ff0000 >> 16)" "$((0xffffffff << (32 - $cidrmask)) & 0x0000ff00 >> 8)" "$((0xffffffff << (32 - $cidrmask)) & 0x000000ff)"); echo "$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).$((i4 & m4))")
echo "Calculating base address as: ${base_address}"
sysctl -p
echo "Setting iptables rules"
iptables -t nat -A POSTROUTING -o ${selectInterface[$red_interface]} -s ${base_address}${cidrmask} -j MASQUERADE
iptables -P FORWARD ACCEPT
iptables -A FORWARD -i ${selectInterface[$green_interface]} -o ${selectInterface[$red_interface]} -j ACCEPT
iptables -A FORWARD -i ${selectInterface[$red_interface]} -o ${selectInterface[$green_interface]} -m state --state RELATED,ESTABLISHED -j ACCEPT
netfilter-persistent save
netfilter-persistent reload
echo "iptables rules set, saved, and made persistent"
echo "Fixing services"
systemctl stop systemd-resolved
systemctl disable systemd-resolved
systemctl enable dhclient_enx.service
systemctl start dhclient_enx.service
systemctl start dnsmasq
systemctl enable iptables
systemctl start iptables
chmod -R a+r /var/ftpd/
chown dnsmasq:root -R /var/ftpd/
usermod -d /var/ftpd ftp
timer=10
while [ $timer -gt 0 ]; do
    echo -ne "Install completed, device will reboot in $timer\033[OK\r]"
    sleep 1
    : $((secs--))
done
echo -ne "Install completed, device will reboot in 0\033[OK\r]"
echo ""
echo "Goodbye!"
reboot