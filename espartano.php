<?php

header('x-espartano: ok');
$id = md5(uniqid(rand(), true));

function antiInjection($input) {
    $input = preg_replace("/(from|select|insert|delete|where|drop table|show tables|#|\*|--|\\\\)/i", "", $input);
    $input = trim($input);
    $input = strip_tags($input);
    $input = (get_magic_quotes_gpc()) ? $input : addslashes($input);
    $input = htmlspecialchars($input);
    return $input;
}

foreach ($_GET as $name => $val) {
    $_GET[$name] = antiInjection($val);
}

foreach ($_POST as $name => $val) {
    $_POST[$name] = antiInjection($val);
}

foreach ($_REQUEST as $name => $val) {
    $_REQUEST[$name] = antiInjection($val);
}


$ext_permitido = [
    ' doc',
    'odp',
    'ods',
    'odt',
    'dot',
    
    'jpe',
    'jpeg',
    'jpg',
    'png',
    'gif',
    
    'pdf',
    'ppt',
    'xls',
    'xlsx',
    
    
    'json',
    'xml',
    'csv',
    'rar',
    'tar',
    'zip',
    '7z'
];

$mime_permitido = [
    'application/msword',
    'image/jpeg',
    'image/pjpeg',
    'text/csv',
    'image/gif',
    'application/json',
    'application/vnd.oasis.opendocument.text',
    'application/vnd.oasis.opendocument.spreadsheet',
    'application/vnd.oasis.opendocument.presentation',
    'image/png',
    'application/pdf',
    'application/vnd.ms-powerpoint',
    'application/x-rar-compressed',
    'application/x-tar',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/xml',
    'application/zip',
    'application/x-7z-compressed'
];

//$ext_not = ['php']
foreach ($_FILES as $name => $val) {

    $mime = finfo_file(finfo_open(FILEINFO_MIME_TYPE), $_FILES[$name]['tmp_name']);
    $ext = pathinfo($_FILES[$name]['name'], PATHINFO_EXTENSION);

    if (!in_array($ext, $ext_permitido) || !in_array($mime, $mime_permitido)) {
         echo "Protegido por espartano";
         exit();
    }
}


//function 

    