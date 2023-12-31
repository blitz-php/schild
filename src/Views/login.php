<?= $this->extend(config('auth.views.layout')) ?>

<?= $this->section('title', lang('Auth.login')) ?>

<?= $this->section('content') ?>

    <div class="container d-flex justify-content-center p-5">
        <div class="card col-12 col-md-5 shadow-sm">
            <div class="card-body">
                <h5 class="card-title mb-5"><?= lang('Auth.login') ?></h5>

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

                <?php if (session('message') !== null) : ?>
                	<div class="alert alert-success" role="alert"><?= session('message') ?></div>
                <?php endif ?>

                <form action="<?= url_to('login') ?>" method="post">
                    <!-- Email -->
                    <div class="mb-2">
                        <input type="email" class="form-control" name="email" inputmode="email" autocomplete="email" placeholder="<?= lang('Auth.email') ?>" value="<?= old('email') ?>" required />
                    </div>

                    <!-- Password -->
                    <div class="mb-2">
                        <input type="password" class="form-control" name="password" inputmode="text" autocomplete="current-password" placeholder="<?= lang('Auth.password') ?>" required />
                    </div>

                    <!-- Remember me -->
                    <?php if (config('auth.session.allow_remembering')): ?>
                        <div class="form-check">
                            <label class="form-check-label">
                                <input type="checkbox" name="remember" class="form-check-input">
                                <?= lang('Auth.rememberMe') ?>
                            </label>
                        </div>
                    <?php endif; ?>

                    <div class="d-grid col-12 col-md-8 mx-auto m-3">
                        <button type="submit" class="btn btn-primary btn-block"><?= lang('Auth.login') ?></button>
                    </div>

                    <?php if (config('auth.allow_magic_link_logins')) : ?>
                        <p class="text-center"><?= lang('Auth.forgotPassword') ?> <a href="<?= url_to('magic-link') ?>"><?= lang('Auth.useMagicLink') ?></a></p>
                    <?php endif ?>

                    <?php if (config('auth.allow_registration')) : ?>
                        <p class="text-center"><?= lang('Auth.needAccount') ?> <a href="<?= url_to('register') ?>"><?= lang('Auth.register') ?></a></p>
                    <?php endif ?>

                </form>
            </div>
        </div>
    </div>

<?= $this->endSection() ?>
