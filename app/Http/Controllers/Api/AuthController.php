<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function index(Request $request)
    {
        return response()->json(['user' => $request->user()]);
    }
    public function register(Request $request)
    {
        // Validate the request data
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255',
            'password' => 'required|string|min:6|confirmed',
        ]);

        // Check if a user with the provided email already exists
        $existingUser = User::where('email', $request->email)->first();
        if ($existingUser) {
            return response()->json(['message' => 'Email already registered'], 422);
        }

        // Create a new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        // Generate a token
        $token = $user->createToken('auth_token')->plainTextToken;

        // Return the user and token
        return response()->json(['user' => $user, 'token' => $token], 201);
    }

    public function login(Request $request)
    {
        // Validate the request data
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        // Attempt to log in the user
        if (!Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            return response()->json(['message' => 'Invalid login credentials'], 401);
        }

        // Get the authenticated user
        $user = Auth::user();

        // Generate a token
        $token = $user->createToken('auth_token')->plainTextToken;

        // Return the user and token
        return response()->json(['token' => $token], 200);
    }

    public function logout(Request $request)
    {
        // Get the authenticated user
        $user = $request->user();

        // Check if the user is logged in
        if ($user) {
            // Revoke the user's token
            $user->tokens()->delete();

            return response()->json(['message' => 'Logout successful']);
        } else {
            return response()->json(['message' => 'User is not logged in'], 401);
        }
    }
    
}
