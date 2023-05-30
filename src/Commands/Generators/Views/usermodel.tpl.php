<@php

namespace {namespace};

use BlitzPHP\Schild\Models\UserModel as ShieldUserModel;

class {class} extends ShieldUserModel
{
    public function __construct()
    {
        parent::__construct();

        $this->allowedFields = [
            ...$this->allowedFields,

            // 'first_name',
        ];
    }
}
