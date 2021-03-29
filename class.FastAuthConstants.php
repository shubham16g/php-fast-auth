<?php
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

class FastAuthConstants
{
    public const DB_NAME = 'eleamapi';
    public const SERVER_NAME = 'localhost';
    public const USER_NAME = 'root';
    public const PASSWORD = '';

    public const OTP_LENGTH = 6;
    public const OTP_CHARACTERS = '0123456789';
    public const OTP_EXPIRES_IN = 3600;

    // public const OTP_CHARACTERS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
}