

######## Getting Ubuntu updates ########

#sudo apt-get upgrade -y
sudo apt-get update -y

############## BEGIN INSTALLATION OF OPENLDAP AND PHPLDAPADMIN #########

######### SETTING PREREQUISITES #########
sudo echo ldap.example.com > /etc/hostname
sudo hostname -F /etc/hostname
config_organization_name=Example
config_fqdn=$(hostname --fqdn)
config_domain=$(hostname --domain)
config_domain_dc="dc=$(echo $config_domain | sed 's/\./,dc=/g')"
config_admin_dn="cn=admin,$config_domain_dc"
config_admin_password=password

sudo echo "127.0.0.1 $config_fqdn" >>/etc/hosts

sudo apt-get install -y --no-install-recommends vim
cat >/etc/vim/vimrc.local <<'EOF'
syntax on
set background=dark
set esckeys
set ruler
set laststatus=2
set nobackup
autocmd BufNewFile,BufRead Vagrantfile set ft=ruby
EOF

# these anwsers were obtained (after installing slapd) with:
#
#   #sudo debconf-show slapd
#   sudo apt-get install debconf-utils
#   # this way you can see the comments:
#   sudo debconf-get-selections
#   # this way you can just see the values needed for debconf-set-selections:
#   sudo debconf-get-selections | grep -E '^slapd\s+' | sort
debconf-set-selections <<EOF
slapd slapd/password1 password $config_admin_password
slapd slapd/password2 password $config_admin_password
slapd slapd/domain string $config_domain
slapd shared/organization string $config_organization_name
EOF


########### OPENLDAP INSTALLATION ###############

sudo apt-get install -y --no-install-recommends slapd ldap-utils

# create the people container.
# NB the `cn=admin,$config_domain_dc` user was automatically created
#    when the slapd package was installed.
ldapadd -D $config_admin_dn -w $config_admin_password <<EOF
dn: ou=people,$config_domain_dc
objectClass: organizationalUnit
ou: people
EOF

##### Populating LDAP #########

cat << USERS | sudo tee -a /tmp/setup
dn: cn=gtosi,ou=people,dc=example,dc=com
Objectclass: inetOrgPerson
cn: Gilles Tosi
sn: TOSI
userpassword: password

dn: cn=admin,ou=people,dc=example,dc=com
Objectclass: inetOrgPerson
cn: Administrators
sn: Support
userpassword: password

dn: cn=jdoe,ou=people,dc=example,dc=com
Objectclass: inetOrgPerson
cn: John Doe
sn: Doe
userpassword: password


dn: ou=groups,dc=example,dc=com
objectclass:organizationalunit
ou: groups
description: generic groups branch

# create the superadmin entry

dn: cn=superadmin,ou=groups,dc=example,dc=com
objectclass: groupofnames
cn: superadmin
description: IT Super Admin Group
# add the group members all of which are 
# assumed to exist under people
member: cn=gtosi,ou=people,dc=example,dc=com
member: cn=admin,ou=people,dc=example,dc=com

# create the fr-team entry

dn: cn=fr-team,ou=groups,dc=example,dc=com
objectclass: groupofnames
cn: fr-team
description: French Group
# add the group members all of which are 
# assumed to exist under people
member: cn=jdoe,ou=people,dc=example,dc=com

# create the fr-team entry

dn: cn=global-team,ou=groups,dc=example,dc=com
objectclass: groupofnames
cn: global-team
description: Gobal Team Group
# add the group members all of which are 
# assumed to exist under groups
member: cn=fr-team,ou=groups,dc=example,dc=com
member: cn=superadmin,ou=groups,dc=example,dc=com

USERS

sudo ldapadd -x -w password -D "cn=admin,dc=example,dc=com" -f /tmp/setup

########### PHPLDAPADMIN INSTALLATION ##########

sudo apt-get install phpldapadmin -y

###### Running phpldapadmin as a virtualhost #######

sudo sed -i "s/# <VirtualHost \*:\*>/<VirtualHost 127.0.0.1:3890>/g" /etc/phpldapadmin/apache.conf
sudo sed -i "s/#     ServerName ldap.example.com/     ServerName ldap.example.com/g" /etc/phpldapadmin/apache.conf
sudo sed -i "s/#     ServerAdmin root@example.com/     ServerAdmin root@example.com/g" /etc/phpldapadmin/apache.conf
sudo sed -i "s/#     DocumentRoot \/usr\/share\/phpldapadmin/     DocumentRoot \/usr\/share\/phpldapadmin/g" /etc/phpldapadmin/apache.conf
sudo sed -i "s/#     ErrorLog logs\/ldap.example.com-error.log/     ErrorLog logs\/ldap.example.com-error.log/g" /etc/phpldapadmin/apache.conf
sudo sed -i "s/#     CustomLog logs\/ldap.example.com-access.log common/     CustomLog logs\/ldap.example.com-access.log common/g" /etc/phpldapadmin/apache.conf
sudo sed -i "s/# <\/VirtualHost>/ <\/VirtualHost>/g" /etc/phpldapadmin/apache.conf
sudo sed -i "s/Listen 80/Listen 127.0.0.1:3890/g" /etc/apache2/ports.conf

sudo mkdir /etc/apache2/logs
sudo rm /etc/apache2/sites-enabled/000-default.conf
sudo service apache2 restart

########### BUILDING AND INSTALLING NGINX+LDAP AUTH FROM SOURCE #########
sudo apt-get install git-core -y
sudo apt-get install build-essential -y
sudo apt-get install libldap2-dev -y
sudo apt-get install libssl-dev -y
sudo apt-get install libpcre3-dev -y

sudo useradd nginx
cd /tmp && sudo wget http://nginx.org/download/nginx-1.10.2.tar.gz
cd /tmp && sudo git clone https://github.com/kvspb/nginx-auth-ldap.git
cd /tmp && sudo tar -xvzf nginx-1.10.2.tar.gz
cd /tmp/nginx-1.10.2 && chmod +x /tmp/nginx-1.10.2/configure
cd /tmp/nginx-1.10.2 && sudo ./configure --user=nginx --group=nginx --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --with-http_gzip_static_module --with-http_stub_status_module --with-http_ssl_module --with-pcre --with-file-aio --with-http_realip_module --add-module=/tmp/nginx-auth-ldap/ --with-ipv6 --with-debug

cd /tmp/nginx-1.10.2 && sudo make

cd /tmp/nginx-1.10.2 && sudo make install

sudo wget https://raw.githubusercontent.com/calvinbui/nginx-init-ubuntu/master/nginx -O /etc/init.d/nginx
sudo chmod +x /etc/init.d/nginx
sudo update-rc.d -f nginx defaults


####### ENABLIC BASIC AUTH FOR NGINX ############

sudo apt-get install apache2-utils -y
sudo htpasswd -bc /etc/nginx/.htpasswd admin password
sudo mkdir /etc/nginx/sites-available/
sudo mkdir /etc/nginx/sites-enabled


######### ENABLING PHPLDAPADMIN VIA NGINX ############

cat << EOF | sudo tee -a /etc/nginx/sites-available/phpldapadmin
server {
        listen 8080;
        listen [::]:8080;

        server_name phpladpadmin;

        location / {
                proxy_pass http://127.0.0.1:3890/;
 auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;
}

         
        access_log /var/log/nginx/access_phpladpadmin.log;
        error_log /var/log/nginx/error_phpldapadmin.log;
}

EOF

sudo ln -nfs /etc/nginx/sites-available/phpldapadmin  /etc/nginx/sites-enabled/phpldapadmin
sudo sed -i "s/http {/http {\ninclude \/etc\/nginx\/sites-enabled\/\*\;/g" /etc/nginx/nginx.conf
sudo service nginx start


########## OXIDIZED INSTALLATION ##########


sudo useradd -b /etc -s /usr/sbin/nologin -m oxidized

#### Oxidized requires ruby > 2.1 - tricks for Ubuntu trusty #######

sudo apt-get install software-properties-common -y
sudo apt-add-repository ppa:brightbox/ruby-ng -y
sudo apt-get update -y
sudo apt-get install ruby2.3 ruby2.3-dev libsqlite3-dev libssl-dev pkg-config cmake libssh2-1-dev -y
sudo gem install oxidized
sudo gem install oxidized-script oxidized-web

cat << DEFAULTFILE |sudo tee -a /etc/nginx/sites-available/oxidized
server {
        listen 80;
        listen [::]:80;

        server_name gss-oxidized.com;

        location / {
                proxy_pass http://127.0.0.1:8888/;
 auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;
}

         location /migration
                 { return 403;}



        access_log /var/log/nginx/access_oxidized.log;
        error_log /var/log/nginx/error_oxidized.log;
}
DEFAULTFILE

sudo ln -nfs /etc/nginx/sites-available/oxidized /etc/nginx/sites-enabled/oxidized
sudo -u oxidized mkdir /etc/oxidized/.config
sudo -u oxidized mkdir /etc/oxidized/.config/oxidized
sudo service nginx restart

cat << CONFIGURATION | sudo -u oxidized tee -a /etc/oxidized/.config/oxidized/config
---
interval: 900
use_syslog: false
debug: false
threads: 30
timeout: 20
retries: 3
prompt: ruby/regexp /^([\w.@-]+[#>:]\s?)#/
#rest: 172.16.112.102:8888
http: 127.0.0.1:8888
vars:
  remove_secret: true
groups: {}
pid: "/etc/oxidized/.config/oxidized/pid"
input:
  default: ssh, telnet
  debug: false
  ssh:
    secure: false
output:
  default: git
  file:
     directory: "/etc/oxidized/.config/oxidized/deviceconfigs"
  git:
     user: Oxidizied
     email: oxidized@cyconet.org
     repo: "/etc/oxidized/.config/oxidized/oxidized.git"
source:
  default: csv
  csv:
    file: "/etc/oxidized/.config/oxidized/router.db"
    delimiter: !ruby/regexp /:/
    map:
      name: 0
      model: 1
      group: 2
      username: 3
      password: 4
    vars_map:
      enable: 5
model_map:
  vsg: vsg
CONFIGURATION

cat << MODEL | sudo tee -a  /var/lib/gems/2.3.0/gems/oxidized-0.18.0/lib/oxidized/model/vsg.rb
class VSG < Oxidized::Model

  #prompt /^([\tw.@()-]+[#>]\s?)#/
  #prompt /([a-z]+#)/

  prompt /([\S]+#)/
  #prompt /(www.opensource.org)/
  comment  '! '

  # example how to handle pager
  #expect /^\s--More--\s+.*$/ do |data, re|
  #  send ' '
  #  data.sub re, ''
  #end

  # non-preferred way to handle additional PW prompt
  #expect /^[\w.]+>$/ do |data|
  #  send "enable\n"
  #  send vars(:enable) + "\n"
  #  data
  #end

  cmd :all do |cfg|
    #cfg.gsub! /\cH+\s{8}/, ''         # example how to handle pager
    #cfg.gsub! /\cH+/, ''              # example how to handle pager

    cfg.each_line.to_a[1..-2].join
  end

  cmd :secret do |cfg|
    cfg.gsub! /^(snmp-server community).*/, '\\1 <configuration removed>'
    cfg.gsub! /^(snmp-server user).*/, '\\1 <configuration removed>'
    cfg.gsub! /username (\S+) privilege (\d+) (\S+).*/, '<secret hidden>'
    cfg.gsub! /^username \S+ password \d \S+/, '<secret hidden>'
    cfg.gsub! /^enable password \d \S+/, '<secret hidden>'
    cfg.gsub! /wpa-psk ascii \d \S+/, '<secret hidden>'
    cfg.gsub! /^tacacs-server key \d \S+/, '<secret hidden>'
    cfg
  end

  cmd 'show version' do |cfg|
    comment cfg.lines.first
  end

  #cmd 'show inventory' do |cfg|
  #  comment cfg
  #end

  cmd 'show running-config' do |cfg|
    cfg = cfg.each_line.to_a[3..-1]
    cfg = cfg.reject { |line| line.match /^ntp clock-period / }.join
    cfg.gsub! /^Current configuration : [^\n]*\n/, ''
    cfg.gsub! /^\ tunnel\ mpls\ traffic-eng\ bandwidth[^\n]*\n*(
                  (?:\ [^\n]*\n*)*
                  tunnel\ mpls\ traffic-eng\ auto-bw)/mx, '\1'
    cfg
  end

  cfg :telnet do
    username /^Username:/
    password /^Password:/
  end

  cfg :telnet, :ssh do
    post_login 'terminal length 0'
    post_login 'terminal width 0'
    # preferred way to handle additional passwords
    if vars :enable
      post_login do
        send "enable\n"
        cmd vars(:enable)
      end
    end
    pre_logout 'exit'
  end

end
MODEL

cat << REFERENCES | sudo -u oxidized tee -a /etc/oxidized/.config/oxidized/router.db
VSG-1:vsg:UAT:oxidized:test:enable
VSG-2:vsg:UAT:oxidized:test:enable
VSG-4:vsg:PRD:oxidized:test:enable
VSG-5:vsg:PRD:oxidized:test:enable

REFERENCES

sudo cp /vagrant/service.sh /etc/init.d/oxidized

sudo chmod +x /etc/init.d/oxidized
sudo update-rc.d oxidized defaults
sudo service oxidized start
