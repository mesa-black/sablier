<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;

class VaultController
{
    public function store(Request $request): string
    {
        $sealed = Crypt::encryptString($request->input('note'));
        $again = encrypt($request->input('other'));

        return $sealed.$again;
    }

    public function register(Request $request): bool
    {
        $hash = Hash::make($request->input('password'));

        return Hash::check($request->input('password'), $hash) && bcrypt('x') !== '';
    }
}
