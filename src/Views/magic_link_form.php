<?= $this->extend(config('auth.views.layout')) ?>

<?= $this->section('title', lang('Auth.useMagicLink')) ?>

<?= $this->section('content') ?>

<div class="container d-flex justify-content-center p-5">
    <div class="card col-12 col-md-5 shadow-sm">
        <div class="card-body">
            <h5 class="card-title mb-5"><?= lang('Auth.useMagicLink') ?></h5>

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

            <form action="<?= url_to('magic-link') ?>" method="post">

                <!-- Email -->
                <div class="mb-2">
                    <input type="email" class="form-control" name="email" autocomplete="email" placeholder="<?= lang('Auth.email') ?>"
                           value="<?= old('email', auth()->user()?->email) ?>" required />
                </div>

                <div class="d-grid col-12 col-md-8 mx-auto m-3">
                    <button type="submit" class="btn btn-primary btn-block"><?= lang('Auth.send') ?></button>
                </div>

            </form>

            <p class="text-center"><a href="<?= url_to('login') ?>"><?= lang('Auth.backToLogin') ?></a></p>
        </div>
    </div>
</div>

<?= $this->endSection() ?>
