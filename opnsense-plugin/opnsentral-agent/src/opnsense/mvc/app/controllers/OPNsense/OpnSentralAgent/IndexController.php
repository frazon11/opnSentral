<?php

declare(strict_types=1);

namespace OPNsense\OpnSentralAgent;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/OpnSentralAgent/index');
    }
}
