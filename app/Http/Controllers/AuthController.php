<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AuthController extends Controller
{
    // Register Function name , email & pwd is required
    public function register (Request $request){
        $validated_result= $request->validate([
            'name' => 'required',
            'email' => 'required',
            'password' => 'required',
        ]);
        // add validated result to user and passe it to create function
        $user = User::create([
            'name' => validated_result['name'],
            'email' => validated_result['email'],
            'password' => bycrpt(validated_result['email']),
        ]);

    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json([
        'token' => $token,
        'user' => $user,

    ],201);
    }

    //login screen email & pwd are reuired cannot be null

    public function login (Request $request){
        $validated_result= $request->validate([
            'email' => 'required',
            'password' => 'required',
        ]);

        //this condition validate the result

        if(!Auth()->attempt($validated_result)){
            return response()->json([
                'message' => 'Invalid Credentials',
            ],401);
        }

        $user = Auth::user();

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'token' => $token,
            'user' => $user,

        ],200);
    }

    public function logout (Request $request){
        $request->user()->currentAccessToken()->delete();
        return response()->json([
            'message' => 'Logout Successfully',
        ],200);
    }   
        
}
