<?php

namespace App\Http\Controllers;

use App\Models\User; // Import User model
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth; // Import Auth facade
use Illuminate\Support\Facades\Hash; // Import Hash facade

class AuthController extends Controller
{
    // Register Function: name, email & password are required
    public function register(Request $request)
    {
        $validated_result = $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users,email', // Ensure email is unique and valid
            'password' => 'required|min:8', // Minimum password length
        ]);

        // Create user and hash the password
        $user = User::create([
            'name' => $validated_result['name'],
            'email' => $validated_result['email'],
            'password' => Hash::make($validated_result['password']), // Use Hash::make to hash the password
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'token' => $token,
            'user' => $user,
        ], 201);
    }

    // Login Function: email & password are required
    public function login(Request $request)
    {
        $validated_result = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        // Validate credentials
        if (!Auth::attempt($validated_result)) {
            return response()->json([
                'message' => 'Invalid Credentials',
            ], 401);
        }

        $user = Auth::user();

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'token' => $token,
            'user' => $user,
        ], 200);
    }

    // Logout Function
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json([
            'message' => 'Logout Successfully',
        ], 200);
    }
}