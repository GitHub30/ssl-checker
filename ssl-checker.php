<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: *');
header('Access-Control-Allow-Headers: *');
header('Content-Type: application/json');

$host = $_GET['cn'] ?? 'example.com';

$fp = stream_socket_client(
    "tcp://{$host}:443",
    $error_code,
    $error_message,
    30,
    STREAM_CLIENT_CONNECT,
    stream_context_create([
        'ssl' => [
            'capture_peer_cert'       => true,
            'capture_peer_cert_chain' => true,
            'verify_peer'            => false,
            'verify_peer_name'       => false,
            'SNI_enabled'            => true,
            'peer_name'              => $host,
        ],
    ])
);

if (!$fp) {
    http_response_code(500);
    echo json_encode(compact('error_code', 'error_message'));
    exit;
}

stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
$meta = stream_get_meta_data($fp);
$params = stream_context_get_params($fp);
fclose($fp);

$cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
echo json_encode(compact('meta', 'params', 'cert'), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
