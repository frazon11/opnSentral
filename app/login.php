<?php
require_once __DIR__.'/inc/config.php';
start_session_secure();
$error='';
$adminUser=envv('ADMIN_USER','admin');
$apiKey=trim(envv('ADMIN_API_KEY'));
$apiKeyEnabled=strlen($apiKey)>=32;

function complete_login(string $username,string $method): never
{
    session_regenerate_id(true);
    $_SESSION['auth']=true;
    $_SESSION['username']=$username;
    $_SESSION['auth_method']=$method;
    if(hash_equals('adminfk',$username)){
        $_SESSION['configuration_unlocked']=true;
        $_SESSION['configuration_unlocked_at']=time();
    }
    header('Location: /');
    exit;
}

if($_SERVER['REQUEST_METHOD']==='POST'){
    require_csrf();
    $mode=(string)($_POST['mode']??'password');

    if($mode==='api_key' && $apiKeyEnabled){
        $provided=(string)($_POST['api_key']??'');
        if(strlen($provided)>=32 && hash_equals($apiKey,$provided)){
            complete_login($adminUser,'api_key');
        }
    }else{
        $username=(string)($_POST['username']??'');
        if(
            hash_equals($adminUser,$username)
            && hash_equals(envv('ADMIN_PASSWORD'),(string)($_POST['password']??''))
        ){
            complete_login($username,'password');
        }
    }

    usleep(350000);
    $error=t('login.invalid');
}

require __DIR__.'/inc/header.php';
?>
<section class="login-card">
<h1><?=h(t('login.title'))?></h1>
<?php if($error):?><div class="alert error"><?=h($error)?></div><?php endif;?>

<?php if($apiKeyEnabled): ?>
<form method="post" autocomplete="off">
<input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
<input type="hidden" name="mode" value="api_key">
<label>API key
<input type="password" name="api_key" required minlength="32" autocomplete="off" spellcheck="false">
</label>
<button>Sign in with API key</button>
</form>

<details style="margin-top:18px">
<summary style="cursor:pointer">Use username and password instead</summary>
<form method="post" style="margin-top:12px">
<input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
<input type="hidden" name="mode" value="password">
<label><?=h(t('login.username'))?><input name="username" required autocomplete="username"></label>
<label><?=h(t('login.password'))?><input type="password" name="password" required autocomplete="current-password"></label>
<button><?=h(t('login.button'))?></button>
</form>
</details>
<?php else: ?>
<form method="post">
<input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
<input type="hidden" name="mode" value="password">
<label><?=h(t('login.username'))?><input name="username" required autocomplete="username"></label>
<label><?=h(t('login.password'))?><input type="password" name="password" required autocomplete="current-password"></label>
<button><?=h(t('login.button'))?></button>
</form>
<?php endif; ?>
</section>
<?php require __DIR__.'/inc/footer.php';?>
