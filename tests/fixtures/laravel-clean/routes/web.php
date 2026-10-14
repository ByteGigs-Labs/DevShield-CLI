<?php

Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:5,1');
