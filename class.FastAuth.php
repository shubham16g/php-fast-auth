<?php
require '../class.FastAuthConstants.php';

class FastAuth
{
    const FOR_RESET_PASSWORD = 8;
    const FOR_VERIFY_EMAIL = 7;
    const FOR_VERIFY_MOBILE = 6;
    const FOR_VERIFY_CREATED_ACCOUNT = 5;

    const NOT_REGISTERED = -1;
    const REGISTERED = 1;
    const ANONYMOUS = 0;

    private const TOKEN_EXPIRE_PERIOD = 2419200;

    public function getUser(int $userID)
    {
        return $this->_getPrivateUser('userID', $userID);
    }
    public function getUserByMobileNumber(string $countryCode, string $mobile)
    {
        $userData = $this->_getPrivateUser('mobile', $mobile);
        if ($userData['countryCode' !== $countryCode]) {
            throw new Exception("No user exists with this country code and mobile", 1);
        }
        return $userData;
    }
    public function getUserByEmail(string $email)
    {
        return $this->_getPrivateUser('userID', $email);
    }

    private function _getPrivateUser(string $key, string $value, bool $isAnySignedType = false)
    {
        $query = "SELECT * FROM `fast_auth_users` WHERE `$key` = '$value'";
        if (!$isAnySignedType) {
            $query .= " AND `signedType` = " . self::REGISTERED;
        }
        $res = mysqli_query($this->conn, $query);
        if (!mysqli_num_rows($res)) {
            throw new Exception("No user exists with given $key", 1);
        }
        if ($row = mysqli_fetch_assoc($res)) {
            return $row;
        } else {
            throw new Exception("DB Error", 1);
        }
    }

    public function isUserExist(int $userID)
    {
        return $this->isUserExist('userID', $userID, false);
    }

    // todo make it private
    private function _isUserExist(string $key, string $value, bool $isAnySignedType = false)
    {
        try {
            $this->_getPrivateUser($key, $value, $isAnySignedType);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    private function parseUser(array $userArray = [])
    {
        return $userArray;
    }

    public function __construct()
    {
        $this->conn = mysqli_connect(FastAuthConstants::SERVER_NAME, FastAuthConstants::USER_NAME, FastAuthConstants::PASSWORD, FastAuthConstants::DB_NAME);
        mysqli_options($this->conn, MYSQLI_OPT_INT_AND_FLOAT_NATIVE, TRUE);

        $createUsersTable = "CREATE TABLE IF NOT EXISTS `fast_auth_users` (
        `userID` INT(11) NOT NULL AUTO_INCREMENT ,
        `email` VARCHAR(255) NULL ,
        `emailVerified` BOOLEAN NOT NULL default false ,
        `countryCode` VARCHAR(5) NULL ,
        `mobile` VARCHAR(255) NULL ,
        `mobileVerified` BOOLEAN NOT NULL default false ,
        `passwordHash` VARCHAR(255) NOT NULL ,
        `name` VARCHAR(255) NOT NULL default '',
        `profileURL` VARCHAR(255) NULL ,
        `disabled` BOOLEAN NOT NULL default false ,
        `createdAt` DATETIME NOT NULL ,
        `passwordUpdatedAt` DATETIME NOT NULL ,
        `signedType` TINYINT(1) NOT NULL default " . self::NOT_REGISTERED . ",
        `extraJson` JSON NULL ,
        PRIMARY KEY (`userID`)
        ) AUTO_INCREMENT = 10000;";

        $createTokensTable = "CREATE TABLE IF NOT EXISTS `fast_auth_tokens` (
        `token` VARCHAR(255) NOT NULL ,
        `userID` INT(11) NOT NULL ,
        `createdAt` DATETIME NOT NULL ,
        `expiresIn` INT(11) NOT NULL ,
        `expirePeriod` INT(11) NOT NULL ,
        `disabled` BOOLEAN NOT NULL default false ,
        `deviceID` VARCHAR(255) NULL ,
        `deviceName` VARCHAR(255) NULL ,
        `deviceType` VARCHAR(255) NULL ,
        PRIMARY KEY (`token`)
        );";

        $createOTPsTable = "CREATE TABLE IF NOT EXISTS `fast_auth_otps` (
        `id` INT(11) NOT NULL AUTO_INCREMENT,
        `userID` INT(11) NOT NULL ,
        `otpHash` VARCHAR(255) NOT NULL ,
        `for` INT(11) NOT NULL ,
        `createdAt` DATETIME NOT NULL ,
        `expiresIn` INT(11) NOT NULL default 3600,
        PRIMARY KEY (`id`)
        );";

        mysqli_query($this->conn, $createUsersTable);
        // echo "<br>--------------<br>";
        mysqli_query($this->conn, $createTokensTable);
        // echo "<br>--------------<br>";
        mysqli_query($this->conn, $createOTPsTable);
        // echo "<br>--------------<br>";
    }

    public function createUserWithEmail(string $email, string $password, string $name, string $profileURL = null, array $extraJson = null, int $userID = null)
    {
        return $this->_createUser(['email' => $email, 'emailVerified' => 1], $password, $name, $profileURL, $extraJson, $userID);
    }
    public function createUserWithMobile(string $countryCode, string $mobile, string $password, string $name, string $profileURL = null, array $extraJson = null, int $userID = null)
    {
        return $this->_createUser(['countryCode' => $countryCode, 'mobile' => $mobile, 'mobileVerified' => 1], $password, $name, $profileURL, $extraJson, $userID);
    }

    public function verifyCreatedUser(int $userID, string $otp)
    {
        $this->_verifyOTP($userID, $otp, self::FOR_VERIFY_CREATED_ACCOUNT);
        $this->_clearOTP($userID, $otp, self::FOR_VERIFY_CREATED_ACCOUNT);
        return $this->_updateUser($userID, ['signedType' => self::REGISTERED]);
    }

    // todo forceCreateUserWith* Function

    private function _createUser(array $params, string $password, string $name, string $profileURL = null, array $extraJson = null, int $userID = null, int $signedType = self::NOT_REGISTERED)
    {
        $params['password'] = $password;
        $params['name'] = $name;
        $params['profileURL'] = $profileURL;
        $params['extraJson'] = $extraJson;
        if ($userID == null) {
            $userID = $this->_insertUser($params);
        } else {
            $this->_updateUser($userID, $params);
        }
        if ($signedType != self::NOT_REGISTERED) {
            return $userID;
        }
        $otp = $this->_generateOTP($userID, self::FOR_VERIFY_CREATED_ACCOUNT);
        return ['userID' => $userID, 'otp' => $otp];
    }

    private function _insertUser(array $params)
    {
        $colums = "";
        $values = "";
        foreach ($params as $key => $value) {
            if ($value == null) {
                continue;
            }
            if ($key === 'password') {
                $key = 'passwordHash';
                $value = password_hash($value, PASSWORD_BCRYPT);
            }
            if ($key === 'mobile' || $key === 'email') {
                if ($this->_isUserExist($key, $value)) {
                    throw new Exception("A user alerady exists with same $key", 3);
                }
            }
            $colums .= "`$key`,";
            $values .= "'$value',";
        }
        $currentTime = $this->getCurrentTimeForMySQL();
        $query = "INSERT INTO `fast_auth_users` ($colums `createdAt`, `passwordUpdatedAt`) VALUES ($values '$currentTime', '$currentTime');";
        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("DB Error", 1);
        }
        $q2 = "SELECT userID FROM fast_auth_users WHERE userID = @@Identity";
        $res2 = mysqli_query($this->conn, $q2);
        if (!mysqli_num_rows($res2)) {
            throw new Exception("DB Error", 1);
        }
        if ($row = mysqli_fetch_assoc($res2)) {
            return (int) $row['userID'];
        } else {
            throw new Exception("Unknown Error Occured", 1);
        }
    }

    // **************************** SIGNIN PROCESS *-********************************----*******

    public function signInAnonymously(int $tokenExpirePeriod = self::TOKEN_EXPIRE_PERIOD, string $deviceID = '', string $deviceType = '', string $deviceName = '')
    {
        $userID = $this->_createUser([], '', 'anonymous', null, null, null, self::ANONYMOUS);
        return $this->_tokenSignIn($userID, false, $tokenExpirePeriod, $deviceID, $deviceType, $deviceName);
    }
    public function signInWithEmailAndPassword(string $email, string $password,  int $tokenExpirePeriod = self::TOKEN_EXPIRE_PERIOD, string $deviceID = '', string $deviceType = '', string $deviceName = '')
    {
        return $this->_signIn('email', $email, $password, $deviceID, $deviceType, $deviceName, $tokenExpirePeriod);
    }
    public function signInWithMobileAndPassword(string $countryCode, string $mobile, string $password,  int $tokenExpirePeriod = self::TOKEN_EXPIRE_PERIOD, string $deviceID = '', string $deviceType = '', string $deviceName = '')
    {
        return $this->_signIn('mobile', $mobile, $password, $deviceID, $deviceType, $deviceName, $tokenExpirePeriod, $countryCode);
    }

    public function forceSignIn(int $userID, int $tokenExpirePeriod = self::TOKEN_EXPIRE_PERIOD, string $deviceID = '', string $deviceType = '', string $deviceName = '')
    {
        return $this->_signIn('userID', $userID, '', $deviceID, $deviceType, $deviceName, $tokenExpirePeriod, null, true);
    }

    private function _signIn(string $key, string $value, string $password, string $deviceID, string $deviceType, string $deviceName, int $expirePeriod, string $countryCode = null, bool $isForced = false)
    {
        $userArray = $this->_getPrivateUser($key, $value);
        if ($userArray == null) {
            throw new Exception("No user Exists with this $key", 1);
        } elseif (!$isForced && $countryCode != null && $userArray['countryCode'] !== $countryCode) {
            throw new Exception("Incorrect country code", 1);
        } elseif (!$isForced && !password_verify($password, $userArray['passwordHash'])) {
            throw new Exception("Incorrect Password", 1);
        } elseif ($userArray['disabled'] == 1) {
            throw new Exception("This user is disabled", 1);
        } else {
            return $this->_tokenSignIn($userArray['userID'], true, $expirePeriod, $deviceID, $deviceType, $deviceName);
        }
    }

    private function _tokenSignIn(int $userID, bool $isSigned, int $expirePeriod, string $deviceID, string $deviceType, string $deviceName)
    {
        $token = $this->randStr();
        $currentTime = $this->getCurrentTimeForMySQL();
        $query = "INSERT INTO `fast_auth_tokens` (`token`,`userID`,`deviceID`,`deviceType`,`deviceName`, `createdAt`, `expiresIn`, `expirePeriod`) VALUES
        ('$token', '$userID', '$deviceID', '$deviceType', '$deviceName', '$currentTime' , '$expirePeriod', '$expirePeriod')";

        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("DB Error", 1);
        }
        return [
            'userID' => $userID,
            'token' => $token,
            'isSigned' => $isSigned
        ];
    }

    // ************-*----------------************* OTP Functions ****************************----------

    public function getOtpToResetPassword(int $userID)
    {
        return $this->_generateOTP($userID, self::FOR_RESET_PASSWORD);
    }

    public function getOtpToVerifyEmail(int $userID)
    {
        return $this->_generateOTP($userID, self::FOR_VERIFY_EMAIL);
    }

    public function getOtpToVerifyMobile(int $userID)
    {
        return $this->_generateOTP($userID, self::FOR_VERIFY_MOBILE);
    }

    private function _generateRandomOTP()
    {
        $charactersLength = strlen(FastAuthConstants::OTP_CHARACTERS);
        $randomString = '';
        for ($i = 0; $i < FastAuthConstants::OTP_LENGTH; $i++) {
            $randomString .= FastAuthConstants::OTP_CHARACTERS[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    // if (!$this->_isUserExist('userID', $userID)) {
    // throw new Exception("No user exist with this userID or user is not verified", 1);
    // }
    private function _generateOTP(int $userID, int $for)
    {
        $otp = $this->_generateRandomOTP();
        $otpHash = $this->cryptOTP($otp);
        $currentTime = $this->getCurrentTimeForMySQL();
        $expiresIn = FastAuthConstants::OTP_EXPIRES_IN;

        $query = "INSERT INTO `fast_auth_otps` (`userID`,`otpHash`,`for`,`createdAt`,`expiresIn`) VALUES
        ('$userID', '$otpHash', '$for', '$currentTime', '$expiresIn')";

        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("Error in generating OTP", 1);
        }
        return $otp;
    }

    private function _verifyOTP(int $userID, string $otp, int $for)
    {
        $otpHash = $this->cryptOTP($otp);
        $query = "SELECT `createdAt`, `expiresIn` FROM `fast_auth_otps` WHERE 
        `userID` = '$userID' AND
        `otpHash` = '$otpHash' AND
        `for` = '$for'";
        $res = mysqli_query($this->conn, $query);
        if (!mysqli_num_rows($res)) {
            throw new Exception("Invalid OTP", 1);
        }
        if ($row = mysqli_fetch_assoc($res)) {
            if (!$this->isValidTimePeriod($row['createdAt'], $row['expiresIn'])) {
                throw new Exception("Timeout! OTP Expires", 1);
            }
            return true;
        } else {
            throw new Exception("DB Error", 1);
        }
    }

    private function _clearOTP(int $userID, int $otp, int $for)
    {
        $otpHash = $this->cryptOTP($otp);
        $query = "DELETE FROM `fast_auth_otps` WHERE 
        `userID` = '$userID' AND
        `otpHash` = '$otpHash' AND
        `for` = '$for'";
        mysqli_query($this->conn, $query);
    }

    // *************************************** User Edits ***********-******-*-*--*-**********
    // *************************************** Verifications ***********-******-*-*--*-**********

    public function verifyEmail(int $userID, int $otp)
    {
        if (!$this->_verifyOTP($userID, $otp, self::FOR_VERIFY_EMAIL)) {
            throw new Exception("Unknown Error occured", 1);
        }
        $this->_clearOTP($userID, $otp, self::FOR_VERIFY_EMAIL);
        return $this->forceVerifyEmail($userID);
    }
    public function verifyMobile(int $userID, int $otp)
    {
        if (!$this->_verifyOTP($userID, $otp, self::FOR_VERIFY_MOBILE)) {
            throw new Exception("Unknown Error occured", 1);
        }
        $this->_clearOTP($userID, $otp, self::FOR_VERIFY_MOBILE);
        return $this->forceVerifyMobile($userID);
    }
    public function isValidOtpToResetPassword(int $userID, int $otp)
    {
        return $this->_verifyOTP($userID, $otp, self::FOR_RESET_PASSWORD);
    }
    public function resetPasswordWithOTP(int $userID, string $newPassword, int $otp)
    {
        if (!$this->_verifyOTP($userID, $otp, self::FOR_RESET_PASSWORD)) {
            throw new Exception("Unknown Error occured", 1);
        }
        $this->_clearOTP($userID, $otp, self::FOR_RESET_PASSWORD);
        return $this->forceResetPassword($userID, $newPassword);
    }
    // force
    public function forceVerifyEmail(int $userID)
    {
        return $this->_updateUser($userID, ['emailVerified' => true]);
    }
    // force
    public function forceVerifyMobile(int $userID)
    {
        return $this->_updateUser($userID, ['mobileVerified' => true]);
    }
    // force
    public function forceResetPassword(int $userID, string $newPassword)
    {
        return $this->_updateUser($userID, [
            'passwordHash' => password_hash($newPassword, PASSWORD_BCRYPT),
            'passwordUpdatedAt' => $this->getCurrentTimeForMySQL()
        ]);
    }
    // force
    public function updateUserName(int $userID, string $newName)
    {
        return $this->_updateUser($userID, ['name' => $newName]);
    }
    // force
    public function disableUser(int $userID)
    {
        return $this->_updateUser($userID, ['disabled' => true]);
    }
    // force
    public function enableUser(int $userID)
    {
        return $this->_updateUser($userID, ['disabled' => false]);
    }

    public function forceUpdateUser(int $userID, array $userData)
    {
        $validKeys = ['mobile', 'mobileVerified', 'email', 'emailVerified', 'password', 'name', 'profileURL', 'extraJson'];
        $newArr = [];
        foreach ($userData as $key => $value) {
            if ($this->matchArray($validKeys, $key, false)) {
                if ($key === 'password') {
                    $key = 'passwordHash';
                    $value = password_hash($value, PASSWORD_BCRYPT);
                }
                if ($key === 'mobile' || $key === 'email') {
                    if ($this->_isUserExist($key, $value)) {
                        throw new Exception("A user alerady exists with same $key", 3);
                    }
                }
                $newArr[$key] = $value;
            }
        }
        return $this->_updateUser($userID, $newArr);
    }

    private function _updateUser(int $userID, array $arr)
    {
        $q = "";
        foreach ($arr as $key => $value) {
            if ($value == null) {
                continue;
            }
            $q .= ",`$key`='$value'";
        }
        $q = substr($q, 1);

        $query = "UPDATE `fast_auth_users` SET $q WHERE `userID` = '$userID'";
        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("Unknown Error occured", 1);
        }
        return true;
    }


    // *****************  *** ***************** authentication verify user ---------******

    public function verifyUser(int $userID, string $token)
    {
        $query = "SELECT * FROM `fast_auth_tokens` WHERE `token` = '$token' AND `userID` = '$userID'";
        $res = mysqli_query($this->conn, $query);
        if (!$res) {
            throw new Exception("Unknown Error Occureds", 1);
        }
        if (!mysqli_num_rows($res)) {
            throw new Exception("Invalid token or userID", 1);
        }
        if ($row = mysqli_fetch_assoc($res)) {
            $timeGap = $this->isValidTimePeriod($row['createdAt'], $row['expiresIn']);
            if (!$timeGap) {
                throw new Exception("Token timeout", 1);
            } elseif ($row['disabled']) {
                throw new Exception("Token disabled", 1);
            } else {
                $timeGap = $timeGap + $row['expirePeriod'];
                $q2 = "UPDATE `fast_auth_tokens` SET `expiresIn` = '$timeGap' WHERE `token` = '$token' AND `userID` = '$userID'";
                mysqli_query($this->conn, $q2);
                return $token;
            }
        }
    }

    public function signOutAllDevices(int $userID, string $exceptToken = null)
    {
        $query = "UPDATE `fast_auth_tokens` SET `disabled` = true WHERE `userID` = '$userID'";
        if ($exceptToken) {
            $query .= " AND `token` <> '$exceptToken'";
        }
        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("Unknown Error Occured", 1);
        }
        return true;
    }

    // ********************-*-*-*-*-*-*-*-* UTILS **********-*-*-*-*-*-*-***************

    private function _filterArray($array, $validKeys)
    {
        $newArr = [];
        foreach ($array as $key => $value) {
            if ($this->matchArray($validKeys, $key)) {
                $newArr[$key] = $value;
            }
        }
        return $newArr;
    }

    private function matchArray($array, $key)
    {
        $ret = false;
        foreach ($array as $value) {
            if ($key === $value) {
                $ret = true;
                break;
            }
        }
        return $ret;
    }

    private function isValidTimePeriod(string $createdAt, int $expiresIn)
    {
        $time = strtotime($createdAt) + $expiresIn;
        $currentTime = time();
        if ($time > $currentTime) {
            return $time - $currentTime;
        }
        return false;
    }

    private function cryptOTP(string $otp)
    {
        return openssl_encrypt($otp, "AES-128-ECB", "__^!@XQ@z#$&*^%%Y&$&*^__");
        // return openssl_decrypt($otpHash, "AES-128-ECB", "__^!@XQ@z#$&*^%%Y&$&*^__");
    }

    private function randStr(bool $isRefreshToken = false)
    {
        $time = time();
        $bcrypt = password_hash($time, PASSWORD_BCRYPT);
        if ($isRefreshToken) {
            $bcrypt2 = password_hash($time, PASSWORD_BCRYPT);
            return substr($bcrypt, 8, strlen($bcrypt) - 10) . substr($time, 5) . substr($bcrypt, 39) . substr($bcrypt2, 8, strlen($bcrypt));
        }
        return substr($bcrypt, 7, strlen($bcrypt) - 20) . substr($time, 5) . substr($bcrypt, 27);
    }

    private function getCurrentTimeForMySQL()
    {
        return date('Y-m-d H:i:s', time());
    }
}
