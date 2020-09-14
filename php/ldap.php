<?php

// Exemplo ldapsearch
//
// LDAPTLS_REQCERT=never ldapsearch -v -H ldaps://195.22.21.180 -x -W -b "ou=colaborador,ou=funcionarios,DC=frassinetti,DC=local" -D "CN=moodleuser,CN=Users,DC=frassinetti,DC=local" "(sAMAccountName=*)"
//
//
$settings = array(
  'NAME' => array(
    'host' => 'ldaps://10.0.0.42:636/',
    'port' => '636',
    'bind_rdn' => 'CN=moodleuser,CN=Users,DC=frassinetti,DC=local', //rnd completa do usuario
    'bind_password' => '', // password
    'display_password' => 'XxXxXxX',  //senha mostrada na interface
    'base_dn' => 'ou=colaborador,ou=funcionarios,DC=frassinetti,DC=local', //base_dn (-b)
    'filter' => '(sAMAccountName=*)', //filtro
    'attributes' => array('cn'),
  ),
);

ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option(NULL, LDAP_OPT_REFERRALS, 0);
ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_ALLOW);


// Custom OpenLDAP Configuration for Client Certificates for LDAPS
// Un-comment lines that you may need for configuration

// LDAP - specify file that contains the TLS CA Certificate.
// Can also be used to provide intermediate certificate to trust remote servers.
# $tls_cacert = __DIR__ . '/../../private/ca.crt';
# if (!file_exists($tls_cacert)) die($tls_cacert . ' CA cert does not exist');
# putenv("LDAPTLS_CACERT=$tls_cacert");

// LDAP - specify file that contains the client certificate.
# $tls_cert = __DIR__ . '/../../private/client.crt';
# if (!file_exists($tls_cert)) die($tls_cert . ' client cert does not exist');
# putenv("LDAPTLS_CERT=$tls_cert");

// LDAP - specify file that contains private key w/o password for TLS_CERT.
# $tls_key = __DIR__ . '/../../private/client.key';
# if (!file_exists($tls_key)) die($tls_key . ' client key does not exist');
# putenv("LDAPTLS_KEY=$tls_key");

// LDAP - Allow server certificate check in a TLS session.
# putenv('LDAPTLS_REQCERT=allow');


echo 'LDAPTLS_CERT=' . getenv('LDAPTLS_CERT') . PHP_EOL;
if (getenv('LDAPTLS_CERT')) {
  echo ' hash: ' . exec('openssl x509 -noout -hash -in ' . getenv('LDAPTLS_CERT')) . PHP_EOL;
}
echo 'LDAPTLS_CACERT=' . getenv('LDAPTLS_CACERT') . PHP_EOL;
if (getenv('LDAPTLS_CACERT')) {
  echo ' hash: ' . exec('openssl x509 -noout -hash -in ' . getenv('LDAPTLS_CACERT')) . PHP_EOL;
}
echo 'LDAPTLS_CACERTDIR=' . getenv('LDAPTLS_CACERTDIR') . PHP_EOL;
echo 'LDAPTLS_REQCERT=' . getenv('LDAPTLS_REQCERT') . PHP_EOL;


foreach ($settings as $host => $setting) {
  echo PHP_EOL;
  echo "Attempting to connect to {$setting['host']} on port {$setting['port']}. " . PHP_EOL;

  $resolved_port = $setting['port'];
  if (!is_numeric($resolved_port)) {
    // If it's a string, then attempt to use it as the name of a PHP constant.
    $resolved_port = constant($resolved_port);
  }

  $resolved_address = $setting['host'];
  // PHP ldap_connect function ignores the port option if scheme is
  // included in the host, so we must appened port number to the 'address'
  if (strpos($resolved_address, 'ldap') !== false) {
    $resolved_address = $resolved_address . ":" . $resolved_port;
  }

  $link_identifier = ldap_connect($resolved_address, $resolved_port);

  if (!$link_identifier) {
    echo 'Unable to connect - ' . ldap_error($link_identifier) . PHP_EOL;
    continue;
  }

  echo 'Connected.' . PHP_EOL;

  ldap_set_option($link_identifier, LDAP_OPT_PROTOCOL_VERSION, 3);
  ldap_set_option($link_identifier, LDAP_OPT_REFERRALS, 0);


  echo "Attempting to bind with rdn {$setting['bind_rdn']} and password {$setting['display_password']}." . PHP_EOL;
  if (!ldap_bind($link_identifier, $setting['bind_rdn'], $setting['bind_password'])) {
    echo 'Unable to bind - ' . ldap_error($link_identifier) . PHP_EOL;
    ldap_unbind($link_identifier);
    continue;
  }


  echo 'Bind succeeded.' . PHP_EOL;


  echo "Attempting to search with base_dn {$setting['base_dn']}, filter {$setting['filter']} and attributes " . var_export($setting['attributes'], TRUE) . PHP_EOL;
  $search_result_identifier = ldap_search($link_identifier, $setting['base_dn'], $setting['filter'], $setting['attributes']);
  if (!$search_result_identifier) {
    echo 'Unable to search - ' . ldap_error($link_identifier) . PHP_EOL;
    ldap_unbind($link_identifier);
    continue;
  }


  echo 'Search succeeded.' . PHP_EOL;


  $entries = ldap_get_entries($link_identifier, $search_result_identifier);
  var_dump($entries);
}
?>
