<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;
use App\Http\Controllers\PasswordResetController;
use App\Http\Controllers\Auth\ResetPasswordController;
use App\Http\Controllers\Auth\ForgotPasswordController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('forgot-password', [ForgotPasswordController::class,'sendResetLinkEmail']);
Route::post('reset-password', [ResetPasswordController::class,'reset']);

Route::post('password/email', [UserController::class, 'sendResetLink'])->name('password.email');

Route::post('/register', [UserController::class , 'register'])->name('register');
Route::post('/login', [UserController::class , 'login'])->name('login');
Route::put('/updateuser', [UserController::class , 'updateuser'])->name('updateuser');

