<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */
define('NAMESPACE_DIR', __DIR__ . '/../');
define('NAMESPACE_PREFIX', 'iAchilles\\pjwt\\');

spl_autoload_register(function ($class) {

    $len = strlen(NAMESPACE_PREFIX);
    if (strncmp(NAMESPACE_PREFIX, $class, $len) !== 0) {
        return;
    }
    $relative_class = substr($class, $len);
    $file = NAMESPACE_DIR . str_replace('\\', '/', $relative_class) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});