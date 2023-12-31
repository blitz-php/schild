<?= $this->extend(config('auth.views.layout')) ?>

<?= $this->section('title', lang('Auth.register')) ?>

<?= $this->section('content') ?>

    <div class="container d-flex justify-content-center p-5">
        <div class="card col-12 col-md-5 shadow-sm">
            <div class="card-body">
                <h5 class="card-title mb-5"><?= lang('Auth.register') ?></h5>

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

                <form action="<?= url_to('register') ?>" method="post">
                    <!-- Email -->
                    <div class="mb-2">
                        <input type="email" class="form-control" name="email" inputmode="email" autocomplete="email" placeholder="<?= lang('Auth.email') ?>" value="<?= old('email') ?>" required />
                    </div>

                    <!-- Username -->
                    <div class="mb-4">
                        <input type="text" class="form-control" name="username" inputmode="text" autocomplete="username" placeholder="<?= lang('Auth.username') ?>" value="<?= old('username') ?>" required />
                    </div>

                    <!-- Password -->
                    <div class="mb-2">
                        <input type="password" class="form-control" name="password" inputmode="text" autocomplete="new-password" placeholder="<?= lang('Auth.password') ?>" required />
                    </div>

                    <!-- Password (Again) -->
                    <div class="mb-5">
                        <input type="password" class="form-control" name="password_confirmation" inputmode="text" autocomplete="new-password" placeholder="<?= lang('Auth.passwordConfirm') ?>" required />
                    </div>

                    <div class="d-grid col-12 col-md-8 mx-auto m-3">
                        <button type="submit" class="btn btn-primary btn-block"><?= lang('Auth.register') ?></button>
                    </div>

                    <p class="text-center"><?= lang('Auth.haveAccount') ?> <a href="<?= url_to('login') ?>"><?= lang('Auth.login') ?></a></p>

                </form>
            </div>
        </div>
    </div>

<?= $this->end() ?>
