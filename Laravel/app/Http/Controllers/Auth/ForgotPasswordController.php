<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;

class ForgotPasswordController extends Controller
{
    public function sendResetLinkEmail(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        $response = $this->broker()->sendResetLink(
            $request->only('email')
        );

        return $response == Password::RESET_LINK_SENT
                    ? response()->json(['message' => 'Reset link sent to your email'], 200)
                    : response()->json(['message' => 'Unable to send reset link'], 400);
    }

    protected function broker()
    {
        return Password::broker();
    }
}
