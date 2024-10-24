<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\ApiController;
use App\Http\Controllers\API\AdminController; 

Route::post('register', [ApiController::class, 'register']);
Route::post('login', [ApiController::class, 'login']);
Route::post('verify-otp', [ApiController::class, 'verifyOtp'])->middleware('auth:sanctum');
Route::post('resend-otp', [ApiController::class, 'resendOtp'])->middleware('auth:sanctum');


Route::group([
    "middleware" => ["auth:sanctum"]
], function() {
    Route::get('profile', [ApiController::class, 'profile']);
    Route::get('logout', [ApiController::class, 'logout']);
});


Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');
