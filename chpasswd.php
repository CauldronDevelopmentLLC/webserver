<?php

$cmd = $_REQUEST['cmd'];
$host = $_SERVER['HTTP_HOST'];
$user = $_SERVER['PHP_AUTH_USER'];
$admin = false;

$host = preg_replace('/^www\./', '', $host);

include "/var/www/etc/mysqlauth.php";
#include "/var/www/$host/etc/mysqlauth.php";


function init_db() {
  global $db;

  mysql_query("CREATE DATABASE $db") or
    die("Failed to create database $db " . mysql_error());

  mysql_select_db($db);

  mysql_query("CREATE TABLE `users` ( " .
              "`uid` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT, " .
              "`login` VARCHAR(20) NOT NULL DEFAULT '', " .
              "`pass` VARCHAR(60) NOT NULL DEFAULT '', " .
              "`firstname` VARCHAR(255) NOT NULL DEFAULT '', " .
              "`lastname` VARCHAR(255) NOT NULL DEFAULT '', " .
              "`email` VARCHAR(255) NOT NULL DEFAULT '', " .
              "PRIMARY KEY  (`uid`), " .
              "UNIQUE KEY `login` (`login`) " .
              ") TYPE = MYISAM") or
    die("Failed to create 'users' TABLE: " . mysql_error());

  mysql_query("CREATE TABLE `groups` ( " .
              "`gid` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT, " .
              "`name` VARCHAR(50) NOT NULL DEFAULT '', " .
              "PRIMARY KEY  (`gid`), " .
              "UNIQUE KEY `name` (`name`) " .
              ") TYPE = MYISAM") or
    die("Failed to create 'groups' TABLE: " . mysql_error());

  mysql_query("CREATE TABLE `usergroup` ( " .
              "`uid` INT(10) UNSIGNED NOT NULL DEFAULT '0', " .
              "`gid` INT(10) UNSIGNED NOT NULL DEFAULT '0', " .
              "PRIMARY KEY  (`uid`,`gid`) " .
              ") TYPE = MYISAM") or
    die("Failed to create 'usergroup' TABLE: " . mysql_error());

  mysql_query("INSERT INTO users " .
              "(uid, login, pass, firstname, lastname, email) " .
              "VALUES(1, 'jcoffland', '', 'Joseph', 'Coffland', " .
              "'joseph@coffland.com')") or
    die("Failed to add user jcoffland: " . mysql_error());

  mysql_query("INSERT INTO groups (gid, name) VALUES (1, 'admin')");
  mysql_query("INSERT INTO usergroup (uid, gid) VALUES (1, 1)");

  echo "<h1>Initialized database</h1>";
}

function connect_db() {
  global $dbhost, $dbuser, $dbpass, $db;

  mysql_connect($dbhost, $dbuser, $dbpass) or
    die ('Error connecting to mysql');

  mysql_select_db($db) or
    init_db();
}

function is_admin($user) {
  $result =
    mysql_query("SELECT * FROM usergroup " .
                "LEFT JOIN (groups, users) ON " .
                "(usergroup.gid=groups.gid AND usergroup.uid=users.uid) " .
                "WHERE groups.name='admin' AND users.login='" . $user . "'") or
    die('Query failed: ' . mysql_error());

  return mysql_num_rows($result) > 0;
}

function get_name_options() {
  echo "<select name='user'>";

  $results = mysql_query("SELECT login FROM users");
  while($row = mysql_fetch_array($results, MYSQL_ASSOC)) {
    $login = $row['login'];

    echo "<option value='" . $login . "'";
    if ($login == $_SERVER['PHP_AUTH_USER']) echo " selected='selected'";
    echo ">" . $login . "</option>";
  }

  echo "</select>";
}

function show_status($msg) {
  echo "<h2 style='color:red'>" . $msg . "</h2>";
}

function get_password() {
  global $min_password_length;

  $pass1 = urldecode($_REQUEST['pass1']);
  $pass2 = urldecode($_REQUEST['pass2']);

  if ($pass1 != $pass2) die('Passwords do not match!');
  if (strlen($pass1) < $min_password_length)
    die('Password less than ' . $min_password_length . ' characters.');
  
  $salt = '';
  $count = 9;
  while ($count--) $salt .= chr(rand(64, 126));

  return crypt($pass1, '$1$' . $salt);
}

function get_user() {
  global $_SERVER, $_REQUEST, $admin, $user;
  $login = $_REQUEST['user'];

  if (!strlen($login)) $login = $user;
  //die('User not set');

  if (!$admin && $login != $user) 
    die('Not authorized');

  return $login;
}

# must be before any headers are sent
$login = $_REQUEST['user'];
if ($cmd == 'login' && $user != $login) {
  header("WWW-Authenticate: Basic realm=\"Login $user\"");
  header('HTTP/1.0 401 Unauthorized');
  echo "Logged in as $user";
  exit;
}


connect_db();
$admin = is_admin($user);

# Check admin access
if (strlen($cmd) && !$admin && $cmd != 'set' && $cmd != 'login') {
  header('WWW-Authenticate: Basic realm="Admin"');
  header('HTTP/1.0 401 Unauthorized');  
  echo "Unauthorized command";
  exit;
}


echo "<html><head>";
echo "<style type='text/css'>";
echo "th {text-align: right; width: 150px;}\n";
echo "#users, #groups {";
echo "width: 48%; border: 1px solid black; padding: 5px;";
echo "}\n";
echo "#users {float: left;}\n";
echo "#groups {float: right;}\n";
echo ".th {font-weight: bold;}\n";
echo "</style>";
echo "</head><body>";

if (strlen($cmd)) {
  switch ($cmd) {
  case 'add':
    $login = get_user();
    $pass = get_password();
    mysql_query("INSERT INTO users (login, pass) VALUES ('" . $login .
                "', '" . $pass . "')") or
      die('Error creating user: ' . mysql_error());

    show_status('Added User');
    break;

  case 'del':
    $uid = $_REQUEST['uid'];

    mysql_query("DELETE FROM usergroup WHERE uid='" . $uid . "'") or
      die('Error deleting group associations: ' . mysql_error());

    mysql_query("DELETE FROM users WHERE uid='" . $uid . "'") or
      die('Error deleting user: ' . mysql_error());

    show_status('Deleted User ' . $uid);
    break;

  case 'set':
    $login = get_user();
    $pass = get_password();
    mysql_query("UPDATE users SET pass='" . $pass . "' WHERE login='" .
                $login . "'") or
      die('Error updating password: ' . mysql_error());
    
    show_status('Password Updated');
    break;
    
  case 'addgrp':
    $group = $_REQUEST['group'];
    mysql_query("INSERT INTO groups (name) VALUES ('" . $group . "')") or
      die('Error creating group: ' . mysql_error());
    
    show_status('Added Group ' . $group);
    break;

  case 'delgrp':
    $gid = $_REQUEST['gid'];

    mysql_query("DELETE FROM usergroup WHERE gid='" . $gid . "'") or
      die('Error deleting group associations: ' . mysql_error());

    mysql_query("DELETE FROM groups WHERE gid='" . $gid . "'") or
      die('Error deleting group: ' . mysql_error());

    show_status('Deleted Group ' . $gid);
    break;

  case 'addtogrp':
    $gid = $_REQUEST['gid'];
    $uid = $_REQUEST['uid'];
    mysql_query("INSERT INTO usergroup (uid, gid) VALUES " .
                "('" . $uid . "', '" . $gid . "')") or
      die('Error adding user to group: ' . mysql_error());

    show_status('Added user ' . $uid . " to group " . $gid);
    break;

  case 'delfromgrp':
    $gid = $_REQUEST['gid'];
    $uid = $_REQUEST['uid'];

    mysql_query("DELETE FROM usergroup WHERE gid='" . $gid . "' AND " .
                "uid='" . $uid . "'") or
      die('Error deleting group associations: ' . mysql_error());

    show_status('Removed user ' . $uid . " from group " . $gid);
    break;

  case 'login':
    # Used to require login
    break;

  default:
    show_status('Invalid Command');
    break;
  }
 }

echo "<div id='users'>";
echo "<h2>Change Password:</h2>";
echo "<table>";
echo "<form action='{$_SERVER['PHP_SELF']}' METHOD='post'>\n";
echo "<tr><th>User:</th><td>";

if ($admin) get_name_options();
else {
  echo $user;
  echo "<input type='hidden' value='" . $user . "'/>";
}

echo "</td></tr>";
echo "<tr><th>New Password:</th><td>";
echo "<input type='password' name='pass1'/></td></tr>";
echo "<tr><th>Verify:</th><td>";
echo "<input type='password' name='pass2'/></td></tr>";
echo "<tr><td></td><td>";
echo "<input type='submit' value='Change'/></td></tr>\n";
echo "<input type='hidden' name='cmd' value='set'/>\n";
echo "</form>\n";
echo "</table>";

if ($admin) {
  echo "<h2>Login As:</h2>";
  echo "<table>";
  echo "<form action='{$_SERVER['PHP_SELF']}' METHOD='post'>\n";
  echo "<tr><th>User:</th><td>";
  get_name_options();
  echo "</td></tr><tr><td></td><td>";
  echo "<input type='submit' value='Login'/></td></tr>\n";
  echo "<input type='hidden' name='cmd' value='login'/>\n";
  echo "</form>\n";
  echo "</table>";

  echo "<h2>Add User:</h2>";
  echo "<table>";
  echo "<form action='{$_SERVER['PHP_SELF']}' METHOD='post'>\n";
  echo "<tr><th>User:</th><td>";
  echo "<input type='textfield' name='user'/></td></tr>";
  echo "<tr><th>New Password:</th><td>";
  echo "<input type='password' name='pass1'/></td></tr>";
  echo "<tr><th>Verify:</th><td>";
  echo "<input type='password' name='pass2'/></td></tr>";
  echo "<tr><td></td><td>";
  echo "<input type='submit' value='Add'/></td></tr>\n";
  echo "<input type='hidden' name='cmd' value='add'/>\n";
  echo "</form>\n";
  echo "</table>";

  echo "<h2>Edit User:</h2>";
  echo "<table>";
  echo "<tr><th>Login</th><td class='th'>UID</td>";
  echo "<td class='th' colspan='2'>Member</td>";
  echo "<td class='th' colspan='2'>Non-Member</td>";
  echo "</tr>";

  $results = mysql_query("SELECT uid, login FROM users ORDER BY uid");
  while ($row = mysql_fetch_array($results, MYSQL_ASSOC)) {
    $uid = $row['uid'];
    $login = $row['login'];

    $in = array();
    $out = array();
    $usergroup =
      mysql_query("SELECT groups.gid, name, uid FROM groups " .
                  "LEFT JOIN (usergroup) ON " .
                  "(usergroup.gid=groups.gid AND " .
                  " usergroup.uid='" . $uid . "')") or
      die('Query failed: ' . mysql_error());

    while ($row2 = mysql_fetch_array($usergroup, MYSQL_ASSOC)) {
      $group = array($row2['gid'], $row2['name']);

      if ($row2['uid'] == $uid) $in[] = $group;
      else $out[] = $group;
    }

    echo "<tr><th>" . $login . '</th>';
    echo "<td>" . $uid . '</td>';

    # Groups user is in
    echo "<form action='{$_SERVER['PHP_SELF']}' METHOD='post'><td>";
    echo "<select name='gid'>";
    foreach ($in as $group)
      echo "<option value='" . $group[0] . "'>" . $group[1] . "</option>";
    echo "</select></td><td>";
    echo "<input type='submit'";
    if (!count($in)) echo " disabled='true'";
    echo " value='Remove'/>";
    echo "<input type='hidden' name='uid' value='" . $uid . "'/>";
    echo "<input type='hidden' name='cmd' value='delfromgrp'/>";
    echo "</td></form>";

    # Groups user is not in
    echo "<form action='{$_SERVER['PHP_SELF']}' METHOD='post'><td>";
    echo "<select name='gid'>";
    foreach ($out as $group)
      echo "<option value='" . $group[0] . "'>" . $group[1] . "</option>";
    echo "</select></td><td>";
    echo "<input type='submit'";
    if (!count($out)) echo " disabled='true'";
    echo " value='Add'/>";
    echo "<input type='hidden' name='uid' value='" . $uid . "'/>";
    echo "<input type='hidden' name='cmd' value='addtogrp'/>";
    echo "</td></form>";

    echo "<form action='{$_SERVER['PHP_SELF']}' METHOD='post'><td>";
    echo "<input type='submit' value='Delete User'/>";
    echo "<input type='hidden' name='uid' value='" . $uid . "'/>";
    echo "<input type='hidden' name='cmd' value='del'/>";
    echo "</td></form>";
    echo "</tr>";
  }
  echo "</table>";
 }

echo "</div>";

if ($admin) {
  echo "<div id='groups'>";
  echo "<h2>Add Group</h2>\n";
  echo "<table>";
  echo "<form action='{$_SERVER['PHP_SELF']}' METHOD='post'>\n";
  echo "<tr><th>Group:</th><td>";
  echo "<input type='textfield' name='group'/></td></tr>";
  echo "<tr><th></th><td><input type='submit' value='Add'/></td></tr>\n";
  echo "<input type='hidden' name='cmd' value='addgrp'/>\n";
  echo "</form>\n";
  echo "</table>";

  echo "<h2>Delete Group</h2>\n";
  echo "<table>";
  echo "<tr><th>Name</th><td class='th'>GID</td></tr>";
  $results = mysql_query("SELECT * FROM groups ORDER BY gid");
  while ($row = mysql_fetch_array($results, MYSQL_ASSOC)) {
    $name = $row['name'];
    $gid = $row['gid'];

    echo "<form action='{$_SERVER['PHP_SELF']}' METHOD='post'>\n";
    echo "<tr><th>" . $name . '</th>';
    echo "<td>" . $gid . '</td><td>';
    echo "<input type='submit' value='Delete'/></td></tr>\n";
    echo "<input type='hidden' name='gid' value='" . $gid . "'/>\n";
    echo "<input type='hidden' name='cmd' value='delgrp'/>\n";
    echo "</form>\n";
  }
  echo "</table>";
  echo "</div>";
 }

echo "</body></html>";
?>
