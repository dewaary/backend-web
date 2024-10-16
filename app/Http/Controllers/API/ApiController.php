<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Sonata\GoogleAuthenticator\GoogleAuthenticator;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;

class ApiController extends Controller
{

    public function register(Request $request)
    {
        try {
            $validateuser = Validator::make($request->all(), [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|min:6|confirmed',
                'role' => 'in:user,admin',
                'profile_image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048',
            ]);

            if ($validateuser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateuser->errors()
                ], 401);
            }

            $imagePath = null;
            if ($request->hasFile('profile_image')) {
                $imagePath = $request->file('profile_image')->store('profile_images', 'public');
            }

            $googleAuthenticator = new GoogleAuthenticator();
            $secret = $googleAuthenticator->generateSecret();
            Log::info('Generated Google2FA secret', ['secret' => $secret]);

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'role' => $request->role ?? 'user',
                'profile_image' => $imagePath,
                'google2fa_secret' => $secret,
            ]);

            $otp = $googleAuthenticator->getCode($secret);
            Log::info('Generated OTP', ['otp' => $otp]);

            Mail::raw('Your OTP code is: ' . $otp, function ($message) use ($user) {
                $message->to($user->email)
                        ->subject('Your OTP Code');
            });
            Log::info('OTP email sent to', ['email' => $user->email]);

            return response()->json([
                'status' => true,
                'message' => 'User created successfully. Check your email for OTP.',
                'token' => $user->createToken('API TOKEN')->plainTextToken
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500);
        }
    }

    public function login(Request $request)
    {
        try {
            $validateuser = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required',
            ]);

            if ($validateuser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateuser->errors()
                ], 401);
            }

            if (!Auth::attempt($request->only(['email', 'password']))) {
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid credentials!',
                ], 401);
            }

            $user = Auth::user();

            if (!$user) {
                return response()->json([
                    'status' => false,
                    'message' => 'User not found!',
                ], 404);
            }

            if ($user->google2fa_secret && !$user->otp_verified) {
                return response()->json([
                    'status' => false,
                    'message' => 'OTP not verified. Please verify your OTP.',
                ], 403);
            }

            return response()->json([
                'status' => true,
                'message' => 'Login successful',
                'token' => $user->createToken('API TOKEN')->plainTextToken,
                'is_otp_verified' => true,
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500);
        }
    }

    public function verifyOtp(Request $request)
    {
        try {
            $validateuser = Validator::make($request->all(), [
                'otp' => 'required',
            ]);

            if ($validateuser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateuser->errors()
                ], 401);
            }

            $user = Auth::user();

            if (!$user) {
                return response()->json([
                    'status' => false,
                    'message' => 'User not authenticated or token is invalid',
                ], 401);
            }

            $googleAuthenticator = new GoogleAuthenticator();

            if (!$googleAuthenticator->checkCode($user->google2fa_secret, $request->otp)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid OTP!',
                ], 401);
            }

            $user->otp_verified = true;
            $user->save();

            return response()->json([
                'status' => true,
                'message' => 'OTP successfully verified',
                'token' => $user->createToken('API TOKEN')->plainTextToken,
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500);
        }
    }


    public function profile()
    {
        $userData = auth()->user();

        return response()->json([
            'status' => true,
            'message' => 'Profile Info',
            'data' => $userData,
            'id' => auth()->user()->id,
        ], 200);
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();
        return response()->json([
            'status' => true,
            'message' => 'Successfully Logout',
            'data' => []
        ], 200);
    }
}
