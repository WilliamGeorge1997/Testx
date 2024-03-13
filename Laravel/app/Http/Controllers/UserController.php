<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Mail\ResetPassword;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Laravel\Passport\PersonalAccessTokenResult;


class UserController extends Controller
{

    public function sendResetLink(Request $request)
{
    $request->validate(['email' => 'required|email']);

    $user = User::where('email', $request->email)->first();

    if (!$user) {
        return back()->with('error', 'User not found.');
    }

    $token = Str::random(60);

    DB::table('password_resets')->insert([
        'email' => $user->email,
        'token' => $token,
        'created_at' => now()
    ]);

    Mail::to($user->email)->send(new ResetPassword($token));

    return back()->with('success', 'Reset password link has been sent to your email.');
}


    public function register(Request $request)
{
    $validator = Validator::make($request->all(), [
        'name' => 'required',
        'email' => 'required|email',
        'password' => 'required|min:8|max:30|confirmed',
    ], [
        'name.required' => 'The name field is required.',
        'email.required' => 'The email field is required.',
        'email.email' => 'Please enter a valid email address.',
        'password.required' => 'The password field is required.',
        'password.confirmed' => 'The password confirmation does not match.',
        'password.min' => 'The password must be at least 8 characters.',
        'password.max' => 'The password must be at max 30 characters.',
    ]);

    if ($validator->fails()) {
        $errors = $validator->messages();
        $errorMessage = '';

        if ($errors->has('name')) {
            $errorMessage = $errors->first('name');
        }

        if ($errors->has('email')) {
            $errorMessage = $errors->first('email');
        }

        if ($errors->has('password')) {
            $errorMessage = $errors->first('password');
        }

        if ($errorMessage !== '') {
            $data = [
                'status' => 400,
                'message' => $errorMessage,
            ];

            return response()->json($data, 400);
        }
    } elseif (User::where('email', $request->email)->exists()) {
        $data = [
            'status' => 400,
            'message' => 'Email already exists',
        ];

        return response()->json($data, 400);
    } else {
        $user = new User;
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->save();


        $token = JWTAuth::fromUser($user);

        $data = [
            'status' => 200,
            'message' => 'success',
            'user' => [
                'name' => $user->name,
                'email' => $user->email
            ],
            'token' => $token,
        ];

        return response()->json($data, 200);
    }
}





public function login(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|min:8|max:30',
        ], [
            'email.required' => 'The email field is required.',
            'email.email' => 'Please enter a valid email address.',
            'password.required' => 'The password field is required.',
            'password.min' => 'The password must be at least 8 characters.',
            'password.max' => 'The password must not be greater than 30 characters.',
        ]);


        if ($validator->fails()) {
            $errorMessage = $validator->errors()->first();
            $data = [
                'status' => 400,
                'message' => $errorMessage,
            ];
            return response()->json($data, 400);
        }


        try {
            $credentials = $request->only('email', 'password');
            if (! $token = JWTAuth::attempt($credentials)) {
                $data = [
                    'status' => 401,
                    'message' => 'Invalid credentials',
                ];
                return response()->json($data, 401);
            }
        } catch (JWTException $e) {
            $data = [
                'status' => 500,
                'message' => 'Could not create token',
            ];
            return response()->json($data, 500);
        }


        $user = JWTAuth::user();

        $token = JWTAuth::claims([
        'name' => $user->name,
        'email' => $user->email,
    ])->attempt($credentials);

        $data = [
            'status' => 200,
            'message' => 'success',
            'user' => [
                'name' => $user->name,
                'email' => $user->email,
            ],
            'token' => $token,
        ];
        return response()->json($data, 200);
    }






    public function updateuser(Request $request)
{

    $validator = Validator::make($request->all(), [
        'gender' => 'nullable|in:male,female',
        'phone' => 'nullable|digits:15',
        'about' => 'nullable|max:250',
    ], [
        'gender.in' => 'The gender must be either "male" or "female".',
        'phone.digits' => 'The phone must be exactly 15 digits.',
        'about.max' => 'The about field must not exceed 250 characters.',
    ]);

    if ($validator->fails()) {
        $errorMessage = $validator->errors()->first();
        $data = [
            'status' => 422,
            'message' => $errorMessage,
        ];
        return response()->json($data, 422);
    }

    try {

        $user = JWTAuth::parseToken()->authenticate();
    } catch (\Exception $e) {

        $data = [
            'status' => 401,
            'message' => 'Unauthorized',
        ];
        return response()->json($data, 401);
    }


    if ($request->filled('gender')) {
        $user->gender = $request->gender;
    }

    if ($request->filled('phone')) {
        $user->phone = $request->phone;
    }

    if ($request->filled('about')) {
        $user->about = $request->about;
    }


    $user->save();


    $data = [
        'status' => 200,
        'message' => 'User data updated successfully',
        'user' => $user,
    ];
    return response()->json($data, 200);
}



}
