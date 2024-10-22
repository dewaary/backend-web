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
use Carbon\Carbon;

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
    
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'role' => $request->role ?? 'user',
                'profile_image' => $imagePath,
                'google2fa_secret' => $secret,
                'otp_verified' => false,
                'otp_sent_at' => null,
            ]);
    
            return response()->json([
                'status' => true,
                'message' => 'User created successfully. You can now log in.',
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
    
            $googleAuthenticator = new GoogleAuthenticator();
            $otp = $googleAuthenticator->getCode($user->google2fa_secret);

            Mail::raw('Your OTP code is: ' . $otp, function ($message) use ($user) {
                $message->to($user->email)->subject('Your OTP Code');
            });
    
            $user->otp_sent_at = now();
            $user->save();
    
            return response()->json([
                'status' => true,
                'message' => 'OTP sent successfully. Please check your email for the OTP.',
                'token' => $user->createToken('API TOKEN')->plainTextToken,
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

            $otpSentAt = Carbon::parse($user->otp_sent_at);
            $otpExpiryTime = $otpSentAt->addMinutes(1);

            if (now()->greaterThan($otpExpiryTime)) {
                return response()->json([
                    'status' => false,
                    'message' => 'OTP has expired!',
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
            $user->otp_sent_at = null;
            $user->save();

            $token = $user->createToken('API TOKEN')->plainTextToken;

            return response()->json([
                'status' => true,
                'message' => 'OTP successfully verified',
                'token' => $token,
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

    public function resendOtp(Request $request)
    {
        try {
            $user = Auth::user();
            if (!$user) {
                return response()->json([
                    'status' => false,
                    'message' => 'User not authenticated or token is invalid',
                ], 401);
            }

            $googleAuthenticator = new GoogleAuthenticator();
            $otp = $googleAuthenticator->getCode($user->google2fa_secret);

            Mail::raw('Your new OTP code is: ' . $otp, function ($message) use ($user) {
                $message->to($user->email)->subject('Your New OTP Code');
            });

            $user->otp_sent_at = now();
            $user->save();

            return response()->json([
                'status' => true,
                'message' => 'New OTP sent successfully. Please check your email.',
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500);
        }
    }
}
