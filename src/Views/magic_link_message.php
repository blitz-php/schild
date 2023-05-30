<?= $this->extend(config('auth.views.layout')) ?>

<?= $this->section('title', lang('Auth.useMagicLink')) ?>

<?= $this->section('content') ?>

<div class="container d-flex justify-content-center p-5">
    <div class="card col-12 col-md-5 shadow-sm">
        <div class="card-body">
            <h5 class="card-title mb-5"><?= lang('Auth.useMagicLink') ?></h5>

            <p><b><?= lang('Auth.checkYourEmail') ?></b></p>

            <p><?= lang('Auth.magicLinkDetails', [config('auth.magic_link_lifetime') / 60]) ?></p>
        </div>
    </div>
</div>

<?= $this->endSection() ?>
