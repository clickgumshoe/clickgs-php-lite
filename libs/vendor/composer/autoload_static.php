<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit244360f8c10916dafaea53d09578c331
{
    public static $files = array (
        'ad155f8f1cf0d418fe49e248db8c661b' => __DIR__ . '/..' . '/react/promise/src/functions_include.php',
        '6b06ce8ccf69c43a60a1e48495a034c9' => __DIR__ . '/..' . '/react/promise-timer/src/functions.php',
        '00032f3d1c63c80843348abd4f65f78f' => __DIR__ . '/..' . '/fluentdom/fluentdom/src/FluentDOM.php',
        'd7c9a5138b45deb428e175ae748db2c5' => __DIR__ . '/..' . '/carica/phpcss/src/PhpCss.php',
        'b7187e2c212dd315c666a01c3e4a54d2' => __DIR__ . '/..' . '/fluentdom/selectors-phpcss/src/plugin.php',
    );

    public static $prefixLengthsPsr4 = array (
        'S' => 
        array (
            'Stash\\' => 6,
        ),
        'R' => 
        array (
            'React\\Stream\\' => 13,
            'React\\Socket\\' => 13,
            'React\\Promise\\Timer\\' => 20,
            'React\\Promise\\' => 14,
            'React\\EventLoop\\' => 16,
            'React\\Dns\\' => 10,
            'React\\Cache\\' => 12,
        ),
        'P' => 
        array (
            'Psr\\Log\\' => 8,
            'Psr\\Cache\\' => 10,
            'PhpCss\\' => 7,
        ),
        'M' => 
        array (
            'Monolog\\' => 8,
        ),
        'F' => 
        array (
            'FluentDOM\\PhpCss\\' => 17,
            'FluentDOM\\' => 10,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Stash\\' => 
        array (
            0 => __DIR__ . '/..' . '/tedivm/stash/src/Stash',
        ),
        'React\\Stream\\' => 
        array (
            0 => __DIR__ . '/..' . '/react/stream/src',
        ),
        'React\\Socket\\' => 
        array (
            0 => __DIR__ . '/..' . '/react/socket/src',
        ),
        'React\\Promise\\Timer\\' => 
        array (
            0 => __DIR__ . '/..' . '/react/promise-timer/src',
        ),
        'React\\Promise\\' => 
        array (
            0 => __DIR__ . '/..' . '/react/promise/src',
        ),
        'React\\EventLoop\\' => 
        array (
            0 => __DIR__ . '/..' . '/react/event-loop/src',
        ),
        'React\\Dns\\' => 
        array (
            0 => __DIR__ . '/..' . '/react/dns/src',
        ),
        'React\\Cache\\' => 
        array (
            0 => __DIR__ . '/..' . '/react/cache/src',
        ),
        'Psr\\Log\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/log/Psr/Log',
        ),
        'Psr\\Cache\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/cache/src',
        ),
        'PhpCss\\' => 
        array (
            0 => __DIR__ . '/..' . '/carica/phpcss/src/PhpCss',
        ),
        'Monolog\\' => 
        array (
            0 => __DIR__ . '/..' . '/monolog/monolog/src/Monolog',
        ),
        'FluentDOM\\PhpCss\\' => 
        array (
            0 => __DIR__ . '/..' . '/fluentdom/selectors-phpcss/src',
        ),
        'FluentDOM\\' => 
        array (
            0 => __DIR__ . '/..' . '/fluentdom/fluentdom/src/FluentDOM',
        ),
    );

    public static $prefixesPsr0 = array (
        'E' => 
        array (
            'Evenement' => 
            array (
                0 => __DIR__ . '/..' . '/evenement/evenement/src',
            ),
        ),
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit244360f8c10916dafaea53d09578c331::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit244360f8c10916dafaea53d09578c331::$prefixDirsPsr4;
            $loader->prefixesPsr0 = ComposerStaticInit244360f8c10916dafaea53d09578c331::$prefixesPsr0;

        }, null, ClassLoader::class);
    }
}