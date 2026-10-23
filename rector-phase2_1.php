<?php
/**
 * Phase 2 - run when the app moves to the PHP 8.4 image.
 * These changes use PHP 7.1+ syntax (?Type), so the result no longer runs on PHP 5.6.
 */
use Rector\Config\RectorConfig;
use Rector\Php82\Rector\FuncCall\Utf8DecodeEncodeToMbConvertEncodingRector;
use Rector\Php84\Rector\Param\ExplicitNullableParamTypeRector;
use Rector\ValueObject\PhpVersion;

return RectorConfig::configure()
    ->withPhpVersion(PhpVersion::PHP_84)
    ->withPaths(['/app/html', '/app/cgi-bin'])
    ->withSkip(require __DIR__ . '/rector-skip.php')
    // Docker Desktop on Windows reads the bind-mounted code slowly: give workers more time,
    // use fewer of them and smaller batches (defaults: 120 s timeout, all CPUs, 16 files per job)
    ->withParallel(timeoutSeconds: 900, maxNumberOfProcess: 4, jobSize: 4)
    ->withCache('/tool/.rector-cache-phase2')
    ->withRules([
        ExplicitNullableParamTypeRector::class,          // Foo $x = null -> ?Foo $x = null (328 hits in your report)
        Utf8DecodeEncodeToMbConvertEncodingRector::class,// utf8_encode/decode -> mb_convert_encoding
    ]);
