<?php
namespace App;

require_once 'helper.php';

class Runner
{
    private $cmd;

    public function __construct($cmd)
    {
        $this->cmd = $cmd;
    }

    public function run()
    {
        return system($this->cmd);
    }
}

function direct()
{
    $name = $_GET['name'];
    system("ls " . $name);
}

function sql($db)
{
    $id = $_POST['id'];
    mysqli_query($db, "SELECT * FROM t WHERE id = " . $id);
}

function safe()
{
    $name = $_GET['name'];
    system("ls " . escapeshellarg($name));
}

function stored()
{
    $r = new Runner($_GET['c']);
    $r->run();
}

function page()
{
    echo $_GET['q'];
    $f = $_REQUEST['file'];
    include $f;
}

function loops($items)
{
    foreach ($items as $item) {
        exec($item);
    }
    $x = unserialize($_COOKIE['data']);
    try {
        $y = $_GET['y'];
        eval($y);
    } catch (\Exception $e) {
        echo $e;
    } finally {
        cleanup();
    }
}

function branches($flag)
{
    $x = $_GET['v'];
    if ($flag) {
        $y = $x;
    } else {
        $y = "fixed";
    }
    shell_exec($y);
    return $flag ? 1 : 2;
}
