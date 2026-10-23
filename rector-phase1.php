<?php
/**
 * Phase 1 - run while you are STILL ON PHP 5.6.
 * Every change here produces code that runs on PHP 5.6 *and* 8.4.
 *
 * Run it TWICE: Rector can't analyse a class while its file still contains
 * $s{0} offsets, so PHP 4 constructors in those files are only fixed on the 2nd pass.
 */
use Rector\Config\RectorConfig;
use Rector\Php55\Rector\FuncCall\PregReplaceEModifierRector;
use Rector\Php70\Rector\ClassMethod\Php4ConstructorRector;
use Rector\Php72\Rector\Assign\ListEachRector;
use Rector\Php72\Rector\Assign\ReplaceEachAssignmentWithKeyCurrentRector;
use Rector\Php72\Rector\FuncCall\CreateFunctionToAnonymousFunctionRector;
use Rector\Php72\Rector\While_\WhileEachToForeachRector;
use Rector\Php74\Rector\ArrayDimFetch\CurlyToSquareBracketArrayStringRector;
use Rector\Php74\Rector\Ternary\ParenthesizeNestedTernaryRector;
use Rector\Php82\Rector\Encapsed\VariableInStringInterpolationFixerRector;
use Rector\ValueObject\PhpVersion;

return RectorConfig::configure()
    ->withPhpVersion(PhpVersion::PHP_84)
    ->withPaths(['/app/html', '/app/cgi-bin'])
    ->withSkip(require __DIR__ . '/rector-skip.php')
    ->withCache('/tool/.rector-cache-phase1')
    ->withRules([
        Php4ConstructorRector::class,                    // function ClassName() -> __construct()
        CurlyToSquareBracketArrayStringRector::class,    // $s{0} -> $s[0]
        CreateFunctionToAnonymousFunctionRector::class,  // create_function() -> function () {}
        WhileEachToForeachRector::class,                 // while (list() = each()) -> foreach
        ListEachRector::class,                           // list($k, $v) = each($a) -> key()/current()/next()
        ReplaceEachAssignmentWithKeyCurrentRector::class,// $x = each($a) -> array built from key()/current()
        ParenthesizeNestedTernaryRector::class,          // a ? b : c ? d : e -> (a ? b : c) ? d : e (keeps PHP 5 meaning)
        PregReplaceEModifierRector::class,               // preg_replace('/.../e') -> preg_replace_callback()
        VariableInStringInterpolationFixerRector::class, // "${var}" -> "{$var}"
    ]);
