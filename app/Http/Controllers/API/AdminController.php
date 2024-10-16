<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;

class AdminController extends Controller
{
    public function listUsers()
    {
        $users = User::all();
        return response()->json([
            'status' => true,
            'data' => $users
        ], 200);
    }

    public function deleteUser($id)
    {
        $user = User::find($id);
        if ($user) {
            $user->delete();
            return response()->json([
                'status' => true,
                'message' => 'User deleted successfully'
            ], 200);
        }

        return response()->json([
            'status' => false,
            'message' => 'User not found'
        ], 404);
    }
}
