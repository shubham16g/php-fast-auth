<?php

class FastAuth
{
    const FOR_RESET_PASSWORD = 8;
    const FOR_VERIFY_EMAIL = 7;
    const FOR_VERIFY_MOBILE = 6;
    private const TOKEN_EXPIRE_PERIOD = 2419200;

    private function getCurrentTimeForMySQL()
    {
        return date('Y-m-d H:i:s', time());
    }

    public function getUser(int $userID)
    {
        return $this->getPrivateUser('userID', $userID);
    }
    public function getUserByMobileNumber(string $countryCode, string $mobile)
    {
        $userData = $this->getPrivateUser('mobile', $mobile);
        if ($userData['countryCode' !== $countryCode]) {
            throw new Exception("No user exists with this country code and mobile", 1);
        }
        return $userData;
    }
    public function getUserByEmail(string $email)
    {
        return $this->getPrivateUser('userID', $email);
    }

    private function getPrivateUser(string $key = '', string $value = '')
    {
        $query = "SELECT * FROM `fast_auth_users` WHERE `$key` = '$value'";
        $res = mysqli_query($this->conn, $query);
        if (!mysqli_num_rows($res)) {
            throw new Exception("No user exists with given $key", 1);
            
        }
        if ($row = mysqli_fetch_assoc($res)) {
            return $row;
        }
        return null;
    }

    private function checkPrivateUserExists(string $key, string $value, int $userType = null)
    {
        $query = "SELECT `$key` FROM `fast_auth_users` WHERE `$key` = '$value'";
        if ($userType != null) {
            $query .= " AND `userType` = '$userType'";
        }
        $res = mysqli_query($this->conn, $query);
        if (!$res) {
            return false;
        }
        if (mysqli_num_rows($res)) {
            return true;
        }
        return false;
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
        `userType` INT(11) NOT NULL default 0,
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

    public function createUser(array $params = [])
    {
        $validKeys = ['countryCode', 'mobile', 'mobileVerified', 'email', 'emailVerified', 'password', 'userType', 'name', 'profileURL', 'extraJson'];
        $colums = "";
        $values = "";
        if (!isset($params['mobile']) && !isset($params['email'])) {
            throw new Exception("atleast one from mobile or email is required", 1);
        } elseif (!isset($params['password'])) {
            throw new Exception("password is required", 1);
        }
        // todo create handling for empty and requierd params
        foreach ($params as $key => $value) {
            if ($this->matchArray($validKeys, $key, false)) { //false for or case

                if ($key === 'password') {
                    $key = 'passwordHash';
                    $value = password_hash($value, PASSWORD_BCRYPT);
                }
                if ($key === 'mobile' || $key === 'email') {
                    $userType = (isset($params['userType'])) ? $params['userType'] : 0;
                    if ($this->checkPrivateUserExists($key, $value, $userType)) {
                        throw new Exception("A user alerady exists with same $key", 3);
                    }
                }
                $colums .= "`$key`,";
                $values .= "'$value',";
            }
        }
        $currentTime = $this->getCurrentTimeForMySQL();
        $query = "INSERT INTO `fast_auth_users` ($colums `createdAt`, `passwordUpdatedAt`) VALUES ($values '$currentTime', '$currentTime');";
        return mysqli_query($this->conn, $query);
    }

    // **************************** SIGNIN PROCESS *-********************************----*******
    public function signInWithEmailAndPassword(string $email, string $password, string $deviceID = '', string $deviceType = '', string $deviceName = '', int $expirePeriod = self::TOKEN_EXPIRE_PERIOD)
    {
        return $this->signIn('email', $email, $password, $deviceID, $deviceType, $deviceName, $expirePeriod);
    }
    public function signInWithMobileAndPassword(string $countryCode, string $mobile, string $password, string $deviceID = '', string $deviceType = '', string $deviceName = '', int $expirePeriod = self::TOKEN_EXPIRE_PERIOD)
    {
        return $this->signIn('mobile', $mobile, $password, $deviceID, $deviceType, $deviceName, $expirePeriod, $countryCode);
    }

    private function signIn(string $key, string $value, string $password, string $deviceID, string $deviceType, string $deviceName, int $expirePeriod, string $countryCode = null)
    {
        $userArray = $this->getPrivateUser($key, $value);
        if ($userArray == null) {
            throw new Exception("No user Exists with this $key", 1);
        } elseif ($countryCode != null && $userArray['countryCode'] !== $countryCode) {
            throw new Exception("Incorrect country code", 1);
        } elseif (!password_verify($password, $userArray['passwordHash'])) {
            throw new Exception("Incorrect Password", 1);
        } else {
            $tokenData = $this->getNewToken($userArray['userID'], $expirePeriod, $deviceID, $deviceType, $deviceName);
            return ['userData' => $this->parseUser($userArray), 'tokenData' => $tokenData];
        }
        return null;
    }

    private function getNewToken(int $userID, int $expirePeriod, string $deviceID, string $deviceType, string $deviceName)
    {
        $token = $this->randStr();
        $currentTime = $this->getCurrentTimeForMySQL();
        $query = "INSERT INTO `fast_auth_tokens` (`token`,`userID`,`deviceID`,`deviceType`,`deviceName`, `createdAt`, `expiresIn`, `expirePeriod`) VALUES
        ('$token', '$userID', '$deviceID', '$deviceType', '$deviceName', '$currentTime' , '$expirePeriod', '$expirePeriod')";

        if (mysqli_query($this->conn, $query)) {
            return [
                'token' => $token,
                'deviceID' => $deviceID,
                'deviceType' => $deviceType,
                'deviceName' => $deviceName,
            ];
        }
        return null;
    }

    // ************-*----------------************* OTP Functions ****************************----------

    public function generateOTP(int $userID, int $for, int $expiresIn = 3600)
    {
        $otp = rand(100211, 999968);
        $otpHash = $this->cryptOTP($otp);
        $currentTime = $this->getCurrentTimeForMySQL();

        if (!$this->checkPrivateUserExists('userID', $userID)) {
            throw new Exception("No user exist with this userID", 1);
        }
        $query = "INSERT INTO `fast_auth_otps` (`userID`,`otpHash`,`for`,`createdAt`,`expiresIn`) VALUES
        ('$userID', '$otpHash', '$for', '$currentTime', '$expiresIn')";

        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("Error in generating OTP", 1);
        }
        return $otp;
    }

    public function verifyOTP(int $otp, int $userID, int $for)
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
        }
        return false;
    }

    private function _clearOTP(int $otp, int $userID, int $for)
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
        if (!$this->verifyOTP($otp, $userID, self::FOR_VERIFY_EMAIL)) {
            throw new Exception("Unknown Error occured", 1);
        }
        $this->_clearOTP($otp, $userID, self::FOR_VERIFY_EMAIL);
        return $this->forceVerifyEmail($userID);
    }
    public function verifyMobile(int $userID, int $otp)
    {
        if (!$this->verifyOTP($otp, $userID, self::FOR_VERIFY_MOBILE)) {
            throw new Exception("Unknown Error occured", 1);
        }
        $this->_clearOTP($otp, $userID, self::FOR_VERIFY_MOBILE);
        return $this->forceVerifyMobile($userID);
    }
    public function resetPasswordWithOTP(int $userID, string $newPassword, int $otp)
    {
        if (!$this->verifyOTP($otp, $userID, self::FOR_RESET_PASSWORD)) {
            throw new Exception("Unknown Error occured", 1);
        }
        $this->_clearOTP($otp, $userID, self::FOR_RESET_PASSWORD);
        return $this->forceResetPassword($userID, $newPassword);
    }
    // force
    public function forceVerifyEmail(int $userID)
    {
        return $this->updateUser($userID, ['emailVerified' => true]);
    }
    // force
    public function forceVerifyMobile(int $userID)
    {
        return $this->updateUser($userID, ['mobileVerified' => true]);
    }
    // force
    public function forceResetPassword(int $userID, string $newPassword)
    {

        return $this->updateUser($userID, [
            'passwordHash' => password_hash($newPassword, PASSWORD_BCRYPT),
            'passwordUpdatedAt' => $this->getCurrentTimeForMySQL()
        ]);
    }
    // force
    public function updateUserName(int $userID, string $newName)
    {
        return $this->updateUser($userID, ['name' => $newName]);
    }
    // force
    public function disableUser(int $userID)
    {
        return $this->updateUser($userID, ['disabled' => true]);
    }
    // force
    public function enableUser(int $userID)
    {
        return $this->updateUser($userID, ['disabled' => false]);
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
                    if ($this->checkPrivateUserExists($key, $value)) {
                        throw new Exception("A user alerady exists with same $key", 3);
                    }
                }
                $newArr[$key] = $value;
            }
        }
        return $this->updateUser($userID, $newArr);
    }

    private function updateUser(int $userID, array $arr)
    {
        $q = "";
        foreach ($arr as $key => $value) {
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

    private function matchArray($array, $key, $type)
    {
        $ret = false;
        if ($type == true) {
            $ret = true;
        }
        foreach ($array as $value) {
            if ($type == true) {
                if ($key !== $value) {
                    $ret = false;
                    break;
                }
            } else {
                if ($key === $value) {
                    $ret = true;
                    break;
                }
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

    private function cryptOTP(int $otp)
    {
        return (int) ($otp * 2 - 633);
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
}
