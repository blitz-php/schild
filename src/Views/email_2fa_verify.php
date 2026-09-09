<?= $this->extend(config('auth.views.layout')) ?>

<?= $this->section('title', lang('Auth.email2FATitle')) ?>

<?= $this->section('content') ?>

<div class="container d-flex justify-content-center p-5">
    <div class="card col-12 col-md-5 shadow-sm">
        <div class="card-body">
            <h5 class="card-title mb-5"><?= lang('Auth.emailEnterCode') ?></h5>

            <p><?= lang('Auth.emailConfirmCode') ?></p>

			<?php if($error = $errors->line('default')) : ?>
				<div class="alert alert-danger" role="alert"><?= $error ?></div>
			<?php elseif ($errors->count()): ?>
				<div class="alert alert-danger" role="alert">
					<?php foreach ($errors->all() as $error) : ?>
						<?= $error ?>
						<br>
					<?php endforeach ?>
				</div>
			<?php endif ?>

            <form action="<?= url_to('auth-action-verify') ?>" method="post">
                <!-- Code -->
                <div class="mb-2">
                    <input type="number" class="form-control" name="token" placeholder="000000"
                        inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" required />
                </div>

                <div class="d-grid col-8 mx-auto m-3">
                    <button type="submit" class="btn btn-primary btn-block"><?= lang('Auth.confirm') ?></button>
                </div>

            </form>
        </div>
    </div>
</div>

<?= $this->endSection() ?>
