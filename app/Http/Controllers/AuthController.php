<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|max:255|unique:users',
            'password' => 'required|string|min:5'
        ]);

        if ($validator->fails()) {
            return  response()->json([
                'meta' => [
                    'code' => 422,
                    'status' => 'error',
                    'message' => $validator->errors()
                ],
                'data' => []
            ], 422);
        }

        $user = User::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => bcrypt($request['password']),
            'picture' => env('AVATAR_GENERATOR_URL') . $request['name']
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        if (!$token) {
            return response()->json([
                'meta' => [
                    'code' => 500,
                    'status' => 'error',
                    'message' => "Register failed"
                ],
                'data' => []
            ], 500);
        }

        return response()->json([
            'meta' => [
                'code' => 200,
                'status' => 'success',
                'message' => "User created successfully"
            ],
            'data' => [
                'name' => $user->name,
                'email' => $user->email,
                'picture' => $user->picture,
                'access_token' => [
                    'token' => $token,
                    'token_type' => 'Bearer',
                ]
            ]
        ], 500);
    }

    public function login(Request $request)
    {
        if (!Auth::attempt($request->only('email', 'password'))) {
            return  response()->json([
                'meta' => [
                    'code' => 401,
                    'status' => 'error',
                    'message' => "User not found"
                ],
                'data' => []
            ], 401);
        }

        $user = User::where('email', $request->email)->firstOrFail();
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'meta' => [
                'code' => 200,
                'status' => 'Success',
                'message' => "Successfully login"
            ],
            'data' => [
                'name' => $user->name,
                'email' => $user->email,
                'picture' => $user->picture,
                'access_token' => [
                    'token' => $token,
                    'token_type' => 'Bearer',
                ]
            ]
        ], 200);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json([
            'meta' => [
                'code' => 200,
                'status' => 'Success',
                'message' => "Successfully logout"
            ],
            'data' => []
        ], 200);
    }
}
