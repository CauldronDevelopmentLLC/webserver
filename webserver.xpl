import xmlpl.stdio;
import xmlpl.process;
import xmlpl.xml;
import xmlpl.unistd;
import xmlpl.gen;
import xmlpl.string;

element webserver;
element filenames;
string default_ip;
string default_ipv6;
string install;

string<< config;


element[] getEmails(element e, string domain) {
  if (webserver/@postmaster && e/email) {
    <email name="postmaster" domain=(domain) alias=(webserver/@postmaster)/>
    <email name="abuse" domain=(domain) alias=(webserver/@postmaster)/>
    <email name="dmarc" domain=(domain) alias=(webserver/@postmaster)/>
  }

  foreach (e/email)
    <email domain=(domain)>
      foreach (./@*) Attribute(name(.), value(.));
    </email>
}


element[] getEmails(element e) {
  <emails>
    foreach (e/domain) {
      element domain = .;
      string name = @name;
      getEmails(., name);

      foreach (./alias)
        getEmails(domain, value(@name));

      foreach (./host)
        getEmails(., value(@name) + "." + name);
    }
  </emails>
}


string getAddress(element email) {
  return value(email/@name) + "@" + value(email/@domain);
}


string[] getAddresses(element email) {
  if (email/@name == "") "@" + value(email/@domain);
  else
    foreach (tokenize(email/@name, ", \n\t"))
      . + "@" + value(email/@domain);
}


string getAliases(element email) {
  string result;

  foreach (tokenize(email/@alias, ", \n\t")) {
    if (result != "") result += ",";
    result += .;
    if (!contains(., "@")) result += "@" + value(email/@domain);
  }

  return result;
}


string[] doDomainFile(element e, string name) {
  string ip;
  if (e/@ip) ip = e/@ip;
  else ip = default_ip;

  string ipv6;
  if (e/@ipv6) ip = e/@ipv6;
  else ipv6 = default_ipv6;

  "$TTL    1h\n";
  "$ORIGIN " + name + ".\n";
  "@  1D  IN        SOA " + name + ". mail." + name + ". (\n";
  "                              2002022401 ; serial\n";
  "                              3H ; refresh\n";
  "                              15 ; retry\n";
  "                              1w ; expire\n";
  "                              3h ; minimum\n";
  "                             )\n";
  "       IN  NS     " + name + ". ; in the domain\n";
  "; server host definitions\n";
  name + ". IN A   " + ip + "\n";

  if (!e/host[@name == "www"])
    "www    IN  A      " + ip + " ;web server definition\n";

  if (!e/host[@name == "mail"])
    "mail   IN  A      " + ip + " ;mail server definition\n";

  foreach (e/host) {
    string host_ip;

    if (@ip) host_ip = @ip;
    else host_ip = ip;

    (string)@name + "   IN  A      " + host_ip + "\n";
    "www." + (string)@name + "   IN  A      " + host_ip + "\n";
  }

  :: MX
  name + ". IN MX 1 mail." + name + ". ;MX entry\n";

  :: SPF
  name + ". IN TXT \"v=spf1 a mx ip6:" + ipv6 + " -all\" ;SPF entry\n";

  :: DKIM
  "_domainkey IN TXT \"o=~;\" ;DKIM policy entry\n";
  "_adsp._domainkey IN TXT \"dkim=all\" ;DKIM ADSP entry\n";

  :: DMARC
  "_dmarc IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@" + name +
    "; ruf=mailto:dmarc@" + name +"\" ;DMARC entry\n";
}


string[] doZone(string name, string file) {
  "zone \"" + name + "\" {\n";
  "  type master;\n";
  "  file \"" + file + "\";\n";
  "};\n";
  "\n";
}


string[] doDomain(element e) {
  string name = e/@name;
  string directory = name + "/etc";
  string filename = directory + "/named.conf";
  string pdir = directory;

  if (!exists(pdir))
    (void)system("mkdir -p " + pdir);

  string<< stream = openStringStream(filename);
  redirect (stream) doDomainFile(e, name); 
  flush(stream);
  close(stream);

  doZone(name, install + filename);

  foreach (e/alias) {
    string name = @name;
    string filename = directory + "/" + name + ".named";

    string<< stream = openStringStream(filename);
    redirect (stream) doDomainFile(e, name);
    flush(stream);
    close(stream);

    doZone(@name, install + filename);
  }
}


string[] doDjangoWeb(string domainname, element django, element[] locations) {
  "  Alias /django " + install + domainname + "/django\n";

  foreach (locations) {
    "  <Location \"" + value(@path) + "\">\n";
    "    SetHandler python-program\n";
    "    PythonHandler django.core.handlers.modpython\n";
    "    SetEnv DJANGO_SETTINGS_MODULE " + value(django/@module) +
      ".settings\n";
    "  </Location>\n";
  }
}


string[] doWebBaseConfig(element domain, string name, string root) {
  "  ServerName www." + name + "\n";
  "  ServerAlias " + name;
  foreach (domain/alias)
    " " + value(@name) + " www." + value(@name);
  "\n";

  "  DocumentRoot " + root + "\n";

  "  <Directory " + root + ">\n";
  if (domain/@allow_override)
    "    AllowOverride " + value(domain/@allow_override) + "\n";
  else "    AllowOverride FileInfo Options\n";
  "  </Directory>\n";

  string robots;
  if (domain/@robots) {
    robots = domain/@robots;
    if (left(robots, 1) != "/") robots = name + "/http/" + robots;
  } else if (filenames/@robots) robots = filenames/@robots;
  if (robots != "") {
    if (left(robots, 1) != "/") robots = install + robots;
    "  Alias /robots.txt " + robots + "\n";
  }

  if (domain/cgi) {
    string user = "nobody";
    string group = "nogroup";

    if (domain/cgi/@user) user = domain/cgi/@user;
    if (domain/cgi/@group) group = domain/cgi/@group;

    "  AddHandler cgi-script .cgi\n";
    ::"  SuexecUserGroup " + user + " " + group + "\n";
  }

  foreach (domain/cgi) {
    "  <Location " + value(@path) + ">\n";
    "    Options +ExecCGI\n";
    "  </Location>\n";
  }

  if (domain/list) {
    "  ScriptAlias /mailman/ /usr/lib/cgi-bin/mailman/\n";
    "  <Directory /usr/lib/cgi-bin/mailman/>\n";
    "    AllowOverride None\n";
    "    Options ExecCGI\n";
    "    Order allow,deny\n";
    "    Allow from all\n";
    "  </Directory>\n";
    "  Alias /mailman-icons/ /var/lib/mailman/icons/\n";
    "  Alias /pipermail/ /var/lib/mailman/archives/public/\n";
  }

  if (domain/location[@proxy]) {
    :: Access restrictions applied later
    "  <Proxy *>\n";
    "    Allow from all\n";
    "  </Proxy>\n";
  }

  foreach (domain/config) {
    "\n  # Config Start\n";
    ./text();
    "\n  # Config End\n";
  }
}


string[] doWebDigestAuth(string realm, string file) {
  "    AuthType Digest\n";
  "    AuthName \"" + realm + "\"\n";
  "    AuthDigestProvider file\n";
  "    AuthUserFile " + file + "\n";
}


string scopeAttr(element e, string n) {
  if (!e) return "";
  if (e/@*[name(.) == n]) return e/@*[name(.) == n];
  return scopeAttr(e/.., n);
}


string[] doMySQLAuth(element e) {
  string db = scopeAttr(e, "db");
  string dbuser = scopeAttr(e, "dbuser");
  string dbpass = scopeAttr(e, "dbpass");
  string dbgroups = scopeAttr(e, "dbgroups");

  if (db == "" || dbuser == "" || dbpass == "") return;

  "    AuthType Basic\n";
  "    AuthName \"Please Login\"\n";
  "    AuthUserFile /dev/null\n";
  "    AuthBasicAuthoritative Off\n";
  "    AuthMySQLAuthoritative on\n";
  "    AuthMYSQLEnable on\n";
  "    AuthMySQLHost 127.0.0.1\n";
  "    AuthMySQLUser " + dbuser + "\n";
  "    AuthMySQLPassword " + dbpass + "\n";
  "    AuthMySQLDB " + db + "\n";
  "    AuthMySQLUserTable users\n";
  "    AuthMySQLNameField login\n";
  "    AuthMySQLPasswordField pass\n";
  "    AuthMySQLPwEncryption crypt\n";

  if (e/@public == "true")
    "    <LimitExcept GET>\n";

  if (dbgroups != "") {
    string[] groups = tokenize(dbgroups, ", ");

    "      Require group admin";
    foreach (groups) " " + .;
    "\n";

    "      AuthMySQLGroupTable users,groups,usergroup\n";
    "      AuthMySQLGroupField name\n";
    "      AuthMySQLGroupCondition \"users.uid=usergroup.uid AND ";
    "groups.gid=usergroup.gid\"\n";

  } else "      Require valid-user\n";

  if (e/@public == "true")
    "    </LimitExcept>\n";
}


string[] doWeb(element domain, string name) {
  string directory = name + "/etc";
  string httpdir = name + "/http";
  string filename = directory + "/apache2.conf";
  string pdir = directory;
  string ifile = install + filename;

  if (!exists(pdir)) (void)system("mkdir -p " + pdir);
  if (!exists(httpdir)) (void)system("mkdir -p " + httpdir);

  boolean https = false;
  boolean webmail = domain/email[!@alias];
  boolean svn = domain/@svn == "true";
  boolean websvn = domain/@websvn == "true";
  boolean svnusers = domain/@svnusers == "true";
  boolean mysqlauth = domain/@db;

  https = webmail || svn || domain/location[@dav || @auth];

  string<< stream = openStringStream(filename);
  redirect (stream) {
    if (https) {
      string cert = install + "etc/apache2.pem";
      if (domain/@cert) {
        cert = domain/@cert;
        if (left(cert, 1) != "/") cert = install + directory + "/" + cert;
      }

      "<VirtualHost *:443>\n";
      doWebBaseConfig(domain, name, install + name + "/http");

      "  <IfModule mod_ssl.c>\n";
      "    SSLEngine on\n";
      "    SSLCertificateFile " + cert + "\n";
      
      if (domain/@cert_chain) {
        string chain = domain/@cert_chain;
        if (left(chain, 1) != "/") chain = install + directory + "/" + chain;
        "    SSLCertificateChainFile " + chain + "\n";
      }

      "    SetEnvIf User-Agent \".*MSIE.*\" nokeepalive ssl-unclean-shutdown\n";
      "  </IfModule>\n";

      if (webmail) {
        "  Alias /webmail /usr/share/squirrelmail\n\n";

        "  <Directory /usr/share/squirrelmail>\n";
        "    php_flag register_globals off\n";
        "    Options Indexes FollowSymLinks\n";
        "    <IfModule mod_dir.c>\n";
        "      DirectoryIndex index.php\n";
        "    </IfModule>\n";
        "  </Directory>\n";
      }

      if (domain/django/location[@https != "false"])
        doDjangoWeb(name, domain/django,
          domain/django/location[@https != "false"]);

      if (svn) {
        string realm = "Subversion Repository";
        if (domain/@svnrealm) realm = domain/@svnrealm;

        "  <Location /svn/>\n";
        "    DAV svn\n";
        "    SVNParentPath /var/svn-repos/" + name + "/\n";

        string accessfile = install + directory + "/svnaccess.conf";
        "    AuthzSVNAccessFile " + accessfile + "\n";
        redirect (config) {
          "\n";
          "if [ ! -e \"" + accessfile + "\" ]; then\n";
          "  touch \"" + accessfile + "\"\n";
          "fi\n\n";
        }

        if (mysqlauth) doMySQLAuth(domain);
        else doWebDigestAuth(realm, install + directory + "/passwd");

        if (svnusers) {
          if (!mysqlauth) "    Require valid-user\n";

          "    Satisfy Any\n";

        } else {
          "    <LimitExcept GET PROPFIND OPTIONS REPORT>\n";
          "      Require valid-user\n";
          "    </LimitExcept>\n";
        }
        "  </Location>\n";
      }

      if (websvn) {
        "  Alias /websvn/ /usr/share/websvn/\n";
        "  <Location /websvn/>\n";
        "    Options FollowSymLinks\n";
        "    <IfModule mod_php4.c>\n";
        "      php_flag magic_quotes_gpc Off\n";
        "      php_flag track_vars On\n";
        "    </IfModule>\n";
        "  </Location>\n";
      }

      foreach (domain/location) {
        "  <Location " + value(@path) + ">\n";
        if (@dav == "true") {
          "    DAV On\n";
          "    Options None\n";
          if (@auth != "mysql")
            doWebDigestAuth("Web Dav", install + directory + "/webdav.passwd");
        }
        if (@auth == "mysql") doMySQLAuth(.);
        if (@proxy != "") {
          "    ProxyPass " + value(@proxy) + "\n";
          "    ProxyPassReverse " + value(@proxy) + "\n";
        }
        "  </Location>\n";
      }

      if (domain/@proxy_buffer != "")
        "  ProxyIOBufferSize " + value(domain/@proxy_buffer) + "\n";

      "</VirtualHost>\n";

      if (!domain/@cert)
        redirect(config) {
          "SANS=\"$SANS " + name + "\"\n\n";

          "grep " + name + " " + install +
            "etc/apache2.pem >/dev/null 2>/dev/null\n";
          "if [ $? -ne 0 ]; then REBUILDCERT=1; echo \"" +
            name + " not in cert\"; fi\n";
        }
    }

    "<VirtualHost *>\n";
    doWebBaseConfig(domain, name, install + name + "/http");

    if (domain/django/location[@http != "false"])
      doDjangoWeb(name, domain/django,
        domain/django/location[@http != "false"]);

    foreach (domain/webalias) {
      "  Alias " + value(@src) + " " + value(@dst) + "\n";
      "  <Directory " + value(@dst) + ">\n";
      "    order allow,deny\n";
      "    allow from all\n";
      "  </Directory>\n";        
    }

    foreach (domain/location) {
      "  <Location " + value(@path) + ">\n";

      if (@auth != "" && @public != "true") {
        "    RewriteEngine On\n";
        "    RewriteCond %{HTTPS} off\n";
        "    RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}\n";
      }

      if (@proxy != "") {
        "    ProxyPass " + value(@proxy) + "\n";
        "    ProxyPassReverse " + value(@proxy) + "\n";
      }

      "  </Location>\n";
    }
    "</VirtualHost>\n";
  }

  redirect(config) {
    foreach (domain/alias) {
      "if [ ! -e " + value(@name) + " ]; then\n";
      "  ln -sf " + name + " " + value(@name) + "\n";
      "fi\n";
    }

    foreach (domain/location[@dav == "true"]) {
      string path = install + httpdir + "/" + value(@path);
      "mkdir -p \"" + path + "\"\n";
      "chown -R www-data \"" + path + "\"\n";
    }

    foreach (domain/cgi) {
      string user = "nobody";
      string group = "nogroup";

      if (domain/cgi/@user) user = domain/cgi/@user;
      if (domain/cgi/@group) group = domain/cgi/@group;

      string path = install + httpdir + "/" + value(@path);
      "chown " + user + " \"" + path + "\"\n";
      "chgrp " + group + " \"" + path + "\"\n";
    }
  }

  flush(stream);
  close(stream);

  "Include " + ifile + "\n";
}


void doNamedConf(element e, string filename) {
  string<< stream = openStringStream(filename);
  redirect (stream)
    foreach (e/domain) doDomain(.);
  flush(stream);
  close(stream);

  redirect(config) "\n/etc/init.d/bind9 reload\n";
}


node[] doWebIndex(string name) {
  <li><a href=("http://" + name + "/")>name;</a></li>
}


void doApache2Conf(element e, string filename) {
  string<< stream = openStringStream(filename);
  if (!exists("http")) system("mkdir -p http");
  node<< index = openNodeStream("http/index.html");

  redirect (config)
    "REBUILDCERT=0\n";

  redirect (index)
  <html>
    <head><title>"Cauldron Development LLC - Websites";</title></head>
    <body>
      <h2>"Cauldron Development LLC - Websites";</h2>
      <ul>

      redirect (stream) {
        ::"NameVirtualHost *\n";
        ::"NameVirtualHost *:443\n\n";

        foreach (e/domain) {
          string name = @name;
          if (@web != "false") {
            doWeb(., name);
            redirect(index) doWebIndex("www." + name);
          }

          foreach (./host[@web != "false"]) {
            doWeb(., value(@name) + "." + name);
            redirect(index) doWebIndex(value(@name) + "." + name);
          }
        }

        "<VirtualHost *:443>\n";
        "  DocumentRoot " + install + "/http\n";
        "  <IfModule mod_ssl.c>\n";
        "    SSLEngine on\n";
        "    SSLCertificateFile " + install + "/etc/apache2.pem\n";
        "    SetEnvIf User-Agent \".*MSIE.*\" nokeepalive ";
        "ssl-unclean-shutdown\n";
        "  </IfModule>\n";
        "</VirtualHost>\n\n";

        "<VirtualHost *>\n";
        "  DocumentRoot " + install + "/http\n";
        "</VirtualHost>\n";
      }
    </ul>
    </body>
  </head>
  
  flush(stream);
  close(stream);
  flush(index);
  close(index);

  redirect (config) {
    "if [ $REBUILDCERT -eq 1 -a \"$SANS\" != \"\" ]; then\n";
    "  cd etc/ssl\n";
    "  SANS=$(for i in $SANS; do echo \"www.$i $i\"; done)\n";
    "  ./create_common_cert.sh $SANS\n";
    "  cd ../..\n";
    "fi\n\n";

    "/etc/init.d/apache2 reload\n";
  }

}


string[] doPostfixVhost(element domain, string name) {
  name + "\n";

  foreach (domain/host)
    value(@name) + "." + name + "\n";
}


void doPostfixVhosts(element e, string filename) {
  string<< stream = openStringStream(filename);
  redirect (stream)
    foreach (e/domain[@mail != "false"]) {
      element domain = .;
      doPostfixVhost(domain, @name);

      foreach (domain/alias)
        doPostfixVhost(domain, @name);
    }
  flush(stream);
  close(stream);
}


void doPostfixVmaps(element emails, string filename) {
  string<< stream = openStringStream(filename);
  redirect (stream)
    foreach (emails/email[@alias == ""]) {
      getAddress(.) + " " + value(@domain) + "/" + value(@name) + "/\n";

      redirect (config) {
        string maildir =
          value(webserver/postfix/@maildir) + "/" + value(@domain) + "/" +
            value(@name);

        foreach ("new", "cur", "tmp") {
          string dir = "\"" + maildir + "/" + . + "\"";

          "if [ ! -e " + dir + " ]; then\n";
          "  mkdir -p " + dir + "\n";
          "  chmod 700 " + dir + "\n";
          "fi\n";
        }

        "chown -R " + value(webserver/postfix/@user) + ":" +
          value(webserver/postfix/@group) + " " + maildir + "\n";
      }
    }
  flush(stream);
  close(stream);
}


void doPostfixValias(element emails, string filename) {
  string<< stream = openStringStream(filename);
  redirect (stream)
    foreach (emails/email[@alias != ""]) {
      string aliases = getAliases(.);
      foreach (getAddresses(.)) . + " " + aliases + "\n";
    }

  flush(stream);
  close(stream);
}


string[] doPostfix(element webserver, element emails) {
  :: vhosts
  doPostfixVhosts(webserver, filenames/@vhosts);

  :: vmaps
  doPostfixVmaps(emails, filenames/@vmaps);

  :: valias
  doPostfixValias(emails, filenames/@valias);

  redirect (config) {
    "postmap \"" + value(filenames/@vmaps) + "\"\n";
    "postmap \"" + value(filenames/@valias) + "\"\n";
    "/etc/init.d/postfix reload\n";
  }
}


string[] doDovecot(element emails) {
  string userdb = filenames/@userdb;
  string passdb = filenames/@passdb;

  string<< userDBStream = openStringStream(userdb);

  foreach (emails/email[@alias == ""]) {
    string addr = getAddress(.);

    redirect (userDBStream)
      addr + "::" + value(webserver/dovecot/@uid) + ":" +
      value(webserver/dovecot/@gid) + "::" +
      value(webserver/postfix/@maildir) +
      "/" + value(@domain) + "/:/bin/false::\n";

    redirect (config)
      "if ! grep \"^" + addr + ":\" \"" + passdb + "\" >/dev/null; then\n" +
      "  PASS=\n" +
      "  while [ \"$PASS\" == \"\" ]; do\n" +
      "    echo -n \"Enter initial password for " + addr + ": \"\n" +
      "    read -s PASS\n" +
      "  done\n" +
      "  PASS=\"$(openssl passwd -1 \"$PASS\")\"\n" +
      "  echo \"" + addr + ":$PASS:\" >> \"" + passdb + "\"\n" +
      "fi\n\n";
  }

  flush(userDBStream);
  close(userDBStream);

  redirect (config) {
    "chgrp www-data \"$(dirname \"" + passdb + "\")\"\n";
    "chmod 775 \"$(dirname \"" + passdb + "\")\"\n";
    "chgrp www-data \"" + passdb + "\"\n";
    "chmod 660 \"" + passdb + "\"\n";
    "chmod 644 \"" + userdb + "\"\n";
    "/etc/init.d/dovecot restart\n";
  }  
}


string[] doMailman(element webserver, string mmalias) {
  string<< stream = openStringStream(mmalias);

  redirect (stream) {
    "POSTFIX_STYLE_VIRTUAL_DOMAINS = [";
    foreach (webserver/domain[./list]) {
      string domainname = @name;
      "'" + domainname + "', ";

      foreach (./list) redirect (config) {
        string listname = value(@name);

        "if [ ! -e /var/lib/mailman/archives/public/" + listname +
          " ]; then\n";
        "  echo \"Creating new mailing list " + listname + "\"\n";
        "  /usr/lib/mailman/bin/newlist -q " + listname + "@" + domainname +
          " \"" + value(@email) + "\" \"" + value(@pass) + "\"\n";
        "fi\n\n";
      }
    }
    "]\n";
  }


  flush(stream);
  close(stream);
}


string[] doOpenDKIM(element webserver) {
  string keyTable = filenames/@opendkim_key_table;
  string signingTable = filenames/@opendkim_signing_table;
  string trustedHosts = filenames/@opendkim_trusted_hosts;

  string<< keyTableStream = openStringStream(keyTable);
  string<< signingTableStream = openStringStream(signingTable);
  string<< trustedHostsStream = openStringStream(trustedHosts);

  redirect(trustedHostsStream)
    "127.0.0.1\n" +
    "localhost\n" +
    value(webserver/@ip) + "\n";
    value(webserver/@ipv6) + "\n";

  foreach (webserver/domain) {
    if (@mail == "false") continue;

    string name = @name;
    string directory = install + name + "/etc";
    string keysDir = directory + "/opendkim";

    redirect(config) {
      :: Create domain key
      "\n";
      "if [ ! -e \"" + keysDir + "/default.private\" ]; then\n";
      "  echo \"Generating domain key for " + name + "\"\n";
      "  mkdir -p \"" + keysDir + "\"\n";
      "  opendkim-genkey -D \"" + keysDir + "\" -r -d \"" + name + "\"\n";
      "  chown opendkim:opendkim \"" + keysDir + "/default.private\"\n";
      "fi\n";

      :: Add domain key TXT entry to domain file
      string domainFile = directory + "/named.conf";
      "if [ -e \"" + domainFile + "\" ]; then\n";
      "  if ! grep ^default._domainkey \"" + domainFile +
        "\" >/dev/null; then\n";
      "    cat \"" + keysDir + "/default.txt\" >> \"" + domainFile + "\"\n";
      "  fi\n";
      "fi\n";
    }

    :: Add domain to trusted hosts
    redirect(trustedHostsStream) name + "\n";

    :: Add domain to keys table
    redirect(keyTableStream)
      "default._domainkey." + name + " " + name + ":default:" + keysDir +
      "/default.private\n";

    :: Add domain to signing table
    redirect(signingTableStream)
      name + " default._domainkey." + name + "\n";
  }

  flush(keyTableStream);
  flush(signingTableStream);
  flush(trustedHostsStream);

  close(keyTableStream);
  close(signingTableStream);
  close(trustedHostsStream);

  redirect(config) "\n/etc/init.d/opendkim restart\n";
}


string[] main(document in, string[] args) {
  webserver = in/webserver;
  filenames = webserver/filenames;
  element emails = getEmails(webserver);
  default_ip = webserver/@ip;
  default_ipv6 = webserver/@ipv6;
  install = webserver/@install;

  :: Move to prefix directory
  string cwd = getcwd();
  string pre = ".";
  if (size(args) > 1) {
    pre = args[1];

    if (!exists(pre))
      (void)system("mkdir -p \"" + pre + "\"");      

    if (!chdir(pre))
      throw "Could not open dir '" + pre + "'!";
  }

  :: create directories
  foreach (filenames/@*) {
    string name = dirname(.);
    if (!exists(name))
      (void)system("mkdir -p \"" + name + "\"");
  }

  :: open config script
  config = openStringStream(filenames/@config);
  (void)system("chmod +x \"" + value(filenames/@config) + "\"");

  redirect (config) {
    "#!/bin/bash\n";
    "# Autogenerated webserver configuration script\n\n";

    "OLDDIR=\"$PWD\"\n";
    "cd $(dirname $0)\n";
  }

  try {
    :: opendkim
    doOpenDKIM(webserver);

    :: named.conf
    doNamedConf(webserver, filenames/@named);

    :: apache2.conf
    doApache2Conf(webserver, filenames/@apache2);

    :: mailman
    doMailman(webserver, filenames/@mmalias);

    :: postfix
    doPostfix(webserver, emails);

    :: dovecot
    if (emails/email[@alias == ""]) doDovecot(emails);
  } catch {}

  redirect (config) {
    "cd \"$OLDDIR\"\n";
  }
  flush(config);
  close(config);

  if (size(args) > 1) (void)chdir(cwd);

  "Web server configuration generated successfully.\n";
  "Now copy the files in '" + pre + "' to '" + value(webserver/@install);
  "'\non the target machine with ip address '" + value(webserver/@ip);
  "'\nand run '" + value(webserver/@install) + "/" + value(filenames/@config);
  "' as root.\n";
}
