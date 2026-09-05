#pragma once
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "OneCore.lib")

#define AES_KEY_SIZE    32
#define AES_IV_SIZE     16
