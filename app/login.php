<?php
require_once __DIR__.'/inc/config.php';start_session_secure();$error='';
if($_SERVER['REQUEST_METHOD']==='POST'){require_csrf();$username=(string)($_POST['username']??'');if(hash_equals(envv('ADMIN_USER','admin'),$username)&&hash_equals(envv('ADMIN_PASSWORD'),(string)($_POST['password']??''))){session_regenerate_id(true);$_SESSION['auth']=true;$_SESSION['username']=$username;if(hash_equals('adminfk',$username)){$_SESSION['configuration_unlocked']=true;$_SESSION['configuration_unlocked_at']=time();}header('Location: /');exit;}usleep(350000);$error=t('login.invalid');}
require __DIR__.'/inc/header.php';?>
<section class="login-card"><h1><?=h(t('login.title'))?></h1><?php if($error):?><div class="alert error"><?=h($error)?></div><?php endif;?>
<form method="post"><input type="hidden" name="csrf" value="<?=h(csrf_token())?>"><label><?=h(t('login.username'))?><input name="username" required></label><label><?=h(t('login.password'))?><input type="password" name="password" required></label><button><?=h(t('login.button'))?></button></form></section>
<?php require __DIR__.'/inc/footer.php';?>
