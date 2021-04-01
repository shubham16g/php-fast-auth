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

    public const TOKEN_EXPIRE_PERIOD = 2419200;
    // public const OTP_CHARACTERS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
}

class FastAuth
{
    const FOR_RESET_PASSWORD = 8;
    const FOR_VERIFY_EMAIL = 7;
    const FOR_VERIFY_MOBILE = 6;
    const FOR_VERIFY_CREATED_ACCOUNT = 5;

    private const UID_LENGTH = 16;
    private const TOKEN_LENGTH = 39;
    private const KEY_LENGTH = 32;


    public const CASE_NEW_USER = 5;
    public const CASE_UPDATE_MOBILE = 6;
    public const CASE_UPDATE_EMAIL = 7;
    public const CASE_UPDATE_PASSWORD = 8;
    private const CASE_PRIVATE_PASSWORD_UPDATE = 9;

    public function __construct()
    {
        $this->conn = mysqli_connect(FastAuthConstants::SERVER_NAME, FastAuthConstants::USER_NAME, FastAuthConstants::PASSWORD, FastAuthConstants::DB_NAME);
        mysqli_options($this->conn, MYSQLI_OPT_INT_AND_FLOAT_NATIVE, TRUE);

        $createUsersTable = "CREATE TABLE IF NOT EXISTS `fast_auth_users` (
        `uid` VARCHAR(255) NOT NULL ,
        `email` VARCHAR(255) NULL ,
        `countryCode` VARCHAR(5) NULL ,
        `mobile` VARCHAR(255) NULL ,
        `passwordHash` VARCHAR(255) NULL ,
        `name` VARCHAR(255) NULL ,
        `profileURL` VARCHAR(255) NULL ,
        `disabled` TINYINT(1) NOT NULL default 0 ,
        `createdAt` DATETIME NOT NULL ,
        `passwordUpdatedAt` DATETIME NOT NULL ,
        `isAnonymous` TINYINT(1) NOT NULL default 0,
        `extraJson` JSON NULL ,
        PRIMARY KEY (`uid`)
        ) AUTO_INCREMENT = 10000;";

        $createTempTable = "CREATE TABLE IF NOT EXISTS `fast_auth_temp` (
        `key` VARCHAR(255) NOT NULL ,
        `uid` VARCHAR(255) NOT NULL ,
        `dateCreatedAt` DATE NOT NULL ,
        `case` INT(11) NOT NULL ,
        `data` JSON NULL ,
        PRIMARY KEY (`key`)
        );";

        $createTokensTable = "CREATE TABLE IF NOT EXISTS `fast_auth_tokens` (
        `token` VARCHAR(255) NOT NULL ,
        `uid` INT(11) NOT NULL ,
        `createdAt` DATETIME NOT NULL ,
        `expiresIn` INT(11) NOT NULL ,
        `disabled` TINYINT(1) NOT NULL default 0 ,
        `deviceJson` JSON NULL ,
        PRIMARY KEY (`token`)
        );";

        $createOTPsTable = "CREATE TABLE IF NOT EXISTS `fast_auth_otps` (
        `id` INT(11) NOT NULL AUTO_INCREMENT,
        `key` VARCHAR(255) NOT NULL ,
        `otpHash` VARCHAR(255) NOT NULL ,
        `createdAt` DATETIME NOT NULL ,
        PRIMARY KEY (`id`)
        );";

        mysqli_query($this->conn, $createTempTable);
        // echo "<br>--------------<br>";
        mysqli_query($this->conn, $createUsersTable);
        // echo "<br>--------------<br>";
        mysqli_query($this->conn, $createTokensTable);
        // echo "<br>--------------<br>";
        mysqli_query($this->conn, $createOTPsTable);
        // echo "<br>--------------<br>";
    }

    public function requestNewUserWithEmail(string $email, string $password, string $name, string $profileURL = null, array $extraJson = null, string $uid = null)
    {
        if ($this->_isUserExist('email', $email)) {
            throw new Exception("A user alerady exists with same email", 3);
        }
        return $this->_newTempUser(['email' => $email], $password, $name, $profileURL, $extraJson, $uid);
    }
    public function requestNewUserWithMobile(string $countryCode, string $mobile, string $password, string $name, string $profileURL = null, array $extraJson = null, string $uid = null)
    {
        if ($this->_isUserExist('email', $mobile)) {
            throw new Exception("A user alerady exists with same mobile", 3);
        }
        return $this->_newTempUser(['countryCode' => $countryCode, 'mobile' => $mobile], $password, $name, $profileURL, $extraJson, $uid);
    }

    public function generateOTP(string $key)
    {
        $this->_getKeyData($key);
        $otp = $this->_generateRandomOTP();
        $otpHash = $this->_cryptOTP($otp);
        $currentTime = $this->_getCurrentTimeForMySQL();

        $query = "INSERT INTO `fast_auth_otps` (`key`,`otpHash`,`createdAt`) VALUES
        ('$key', '$otpHash', '$currentTime')";

        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("Error in generating OTP", 1);
        }
        return $otp;
    }

    public function verifyOTP(string $key, string $otp)
    {
        $query = "SELECT `otpHash`, `createdAt` FROM `fast_auth_otps` WHERE `key` = '$key'";
        $res = mysqli_query($this->conn, $query);
        if (!mysqli_num_rows($res)) {
            throw new Exception("No OTP exist with given Key", 1);
        }
        if ($row = mysqli_fetch_assoc($res)) {
            $otpHash = $this->_cryptOTP($otp);
            if (!$this->_isValidTimePeriod($row['createdAt'], FastAuthConstants::OTP_EXPIRES_IN)) {
                throw new Exception("Timeout! OTP Expires", 1);
            } elseif ($otpHash !== $row['otpHash']) {
                throw new Exception("Invalid OTP", 1);
            }
            return $this->_handleVerifySuccess($key);
        } else {
            throw new Exception("DB Error", 1);
        }
    }

    // **************************** SIGNIN PROCESS *-********************************----*******

    public function signInAnonymously(array $deviceJson = null)
    {
        $uid = $this->_randomStr(self::UID_LENGTH);
        $this->_insertUser([
            'isAnonymous' => 1,
        ], $uid);
        return $this->_tokenSignIn($uid, true, $deviceJson);
    }
    public function signInWithEmailAndPassword(string $email, string $password, array $deviceJson = null)
    {
        return $this->_signIn('email', $email, $password, $deviceJson);
    }
    public function signInWithMobileAndPassword(string $countryCode, string $mobile, string $password, array $deviceJson = null)
    {
        return $this->_signIn('mobile', $mobile, $password, $deviceJson, $countryCode);
    }
    public function signInWithUid(string $uid, array $deviceJson = null)
    {
        return $this->_signIn('uid', $uid, null, $deviceJson);
    }

    // ***********5*885*ad5sff*8f*a/8d*f/---------GET USER --------asdfa46546****asdf*a*dsf**adsf********
    public function getUser(string $uid)
    {
        return $this->_getPrivateUser('*', 'uid', $uid);
    }
    public function isValidUser(string $uid)
    {
        return $this->_isUserExist('uid', $uid);
    }
    public function getUserByMobileNumber(string $countryCode, string $mobile)
    {
        $userData = $this->_getPrivateUser('*', 'mobile', $mobile);
        if ($userData['countryCode']!== $countryCode) {
            throw new Exception("No user exists with this country code and mobile", 1);
        }
        return $userData;
    }
    public function getUserByEmail(string $email)
    {
        return $this->_getPrivateUser('*', 'email', $email);
    }

    // *************************************** User Edits ***********-******-*-*--*-**********

    public function requestUpdateMobile(string $uid, string $newCountryCode, string $newMobile)
    {
        return $this->_insertTemp($uid, self::CASE_UPDATE_MOBILE, ['countryCode' => $newCountryCode, 'mobile' => $newMobile], true);
    }

    public function requestUpdateEmail(string $uid, string $newEmail)
    {
        return $this->_insertTemp($uid, self::CASE_UPDATE_EMAIL, ['email' => $newEmail], true);
    }
    public function requestUpdatePassword(string $uid)
    {
        return $this->_insertTemp($uid, self::CASE_UPDATE_PASSWORD, null, true);
    }


    public function updatePassword(string $passwordUpdateKey, string $newPassword)
    {
        $row = $this->_getKeyData($passwordUpdateKey, 'uid');
        return $this->_updateUser([
            'passwordHash' => password_hash($newPassword, PASSWORD_BCRYPT),
            'passwordUpdatedAt' => $this->_getCurrentTimeForMySQL()
        ], $row['uid']);
    }

    public function updatePasswordWithCurrentPassword(string $uid, string $currentPassword, string $newPassword)
    {
        $row = $this->_getPrivateUser('passwordHash', 'uid', $uid);
        if (!password_verify($currentPassword, $row['passwordHash'])) {
            throw new Exception("Password Incorrect", 1);
        }
        return $this->_updateUser([
            'passwordHash' => password_hash($newPassword, PASSWORD_BCRYPT),
            'passwordUpdatedAt' => $this->_getCurrentTimeForMySQL()
        ], $uid);
    }

    // force
    public function updateUserName(string $uid, string $newName)
    {
        return $this->_updateUser(['name' => $newName], $uid);
    }
    // force
    public function disableUser(string $uid)
    {
        return $this->_updateUser(['disabled' => 1], $uid);
    }
    // force
    public function enableUser(string $uid)
    {
        return $this->_updateUser(['disabled' => 0], $uid);
    }


    // *****************  *** ***************** authentication verify user ---------******

    public function verifyUser(string $uid, string $token)
    {
        // todo also check in userTable
        $query = "SELECT * FROM `fast_auth_tokens` WHERE `token` = '$token' AND `uid` = '$uid'";
        $res = mysqli_query($this->conn, $query);
        if (!$res) {
            throw new Exception("Unknown Error Occureds", 1);
        }
        if (!mysqli_num_rows($res)) {
            throw new Exception("Invalid token or uid", 1);
        }
        if ($row = mysqli_fetch_assoc($res)) {
            $timeGap = $this->_isValidTimePeriod($row['createdAt'], $row['expiresIn']);
            if (!$timeGap) {
                throw new Exception("Token timeout", 1);
            } elseif ($row['disabled']) {
                throw new Exception("Token disabled", 1);
            } else {
                $timeGap = $timeGap + FastAuthConstants::TOKEN_EXPIRE_PERIOD;
                $q2 = "UPDATE `fast_auth_tokens` SET `expiresIn` = '$timeGap' WHERE `token` = '$token' AND `uid` = '$uid'";
                mysqli_query($this->conn, $q2);
                return $token;
            }
        }
    }

    public function signOutAllDevices(string $uid, string $exceptToken = null)
    {
        $query = "UPDATE `fast_auth_tokens` SET `disabled` = 1 WHERE `uid` = '$uid'";
        if ($exceptToken) {
            $query .= " AND `token` <> '$exceptToken'";
        }
        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("Unknown Error Occured", 1);
        }
        return true;
    }

    /*   -------  ------- |  \        |   /\   -------  -------
        |      | |      | |   \      |   / \     |     |
        |------  \------  |    \    |   ----     |     -------  Functions:
        |       | \       |     \  |  /     \    |    |
        |      |   \      |      \| /        \   |    -------

*/

    private function _updateUser(array $arr, string $uid)
    {
        $q = "";
        foreach ($arr as $key => $value) {
            if ($value == null) {
                continue;
            }
            $q .= ",`$key`='$value'";
        }
        $q = substr($q, 1);

        $query = "UPDATE `fast_auth_users` SET $q WHERE `uid` = '$uid'";
        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("Unknown Error occured", 1);
        }
        return true;
    }

    private function _getPrivateUser(string $columns, string $key, string $value)
    {
        $query = "SELECT $columns FROM `fast_auth_users` WHERE `$key` = '$value'";
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
    // todo make it private
    private function _isUserExist(string $key, string $value)
    {
        try {
            $this->_getPrivateUser('uid', $key, $value);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    // todo
    private function _handleVerifySuccess(string $key)
    {
        $row = $this->_getKeyData($key, '*');
        // todo change * to column names
        $data = json_decode($row['data']);
        switch ($row['case']) {
            case self::CASE_NEW_USER:
                $this->_insertUser((array)$data, $row['uid']);
                return ['case' => $row['case'], 'uid' => $row['uid']];
                break;
            case self::CASE_UPDATE_PASSWORD:
                $passwordUpdateKey = $this->_insertTemp($row['uid'], self::CASE_PRIVATE_PASSWORD_UPDATE, null, true);
                return ['case' => $row['case'], 'passwordUpdateKey' => $passwordUpdateKey];
                break;
            case self::CASE_UPDATE_EMAIL:
            case self::CASE_UPDATE_MOBILE:
                $this->_updateUser((array)$data, $row['uid']);
                return ['case' => $row['case']];
                break;
            default:
                throw new Exception("Unknown Case Error", 1);

                break;
        }
    }
    // todo forceCreateUserWith* Function
    private function _newTempUser(array $params, string $password, string $name, string $profileURL = null, array $extraJson = null, string $uid = null)
    {
        $params['password'] = $password;
        $params['name'] = $name;
        $params['profileURL'] = $profileURL;
        $params['extraJson'] = $extraJson;
        if ($uid == null) {
            $uid = $this->_randomStr(self::UID_LENGTH);
        }
        return $this->_insertTemp($uid, self::CASE_NEW_USER, $params);
    }

    private function _insertTemp(string $uid, int $case, array $params = null, bool $isUidExist = false)
    {

        if ($isUidExist && !$this->_isUserExist('uid', $uid)) {
            throw new Exception("A user alerady exists with same mobile", 3);
        }

        $key = $this->_randomStr(self::KEY_LENGTH);
        $currentDate = $this->_getCurrentTimeForMySQL(true);

        $query = '';
        if ($params != null) {
            $data = json_encode($this->_filterArray($params));
            $query = "INSERT INTO `fast_auth_temp` (`key`,`uid`,`dateCreatedAt`,`case`,`data`) VALUES ('$key', '$uid', '$currentDate', '$case', '$data');";
        } else {
            $query = "INSERT INTO `fast_auth_temp` (`key`,`uid`,`dateCreatedAt`,`case`) VALUES ('$key', '$uid', '$currentDate', '$case');";
        }

        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("DB Error", 1);
        }
        return $key;
    }
    private function _getKeyData(string $key, string $columns = null)
    {
        if ($columns === null) {
            $columns = '`case`';
        }
        $query = "SELECT $columns FROM `fast_auth_temp` WHERE `key` = '$key'";
        $res = mysqli_query($this->conn, $query);
        if (!$res) {
            throw new Exception("DB Error $query", 1);
        }
        if (!mysqli_num_rows($res)) {
            throw new Exception("This key isn't exist", 1);
        }
        if ($row = mysqli_fetch_assoc($res)) {
            return $row;
        } else {
            throw new Exception("Unknown Error Occur", 1);
        }
    }

    private function _insertUser(array $params, string $uid = null)
    {

        if (isset($params['mobile']) && $this->_isUserExist('mobile', $params['mobile'])) {
            throw new Exception("A user alerady exists with same mobile", 3);
        } elseif (isset($params['email']) && $this->_isUserExist('email', $params['email'])) {
            throw new Exception("A user alerady exists with same email", 3);
        }

        // unset($params['case']);

        $colums = "";
        $values = "";
        foreach ($params as $key => $value) {
            if ($value == null) {
                continue;
            }
            $colums .= "`$key`,";
            $values .= "'$value',";
        }
        $currentTime = $this->_getCurrentTimeForMySQL();
        $query = "INSERT INTO `fast_auth_users` ($colums `uid`, `createdAt`, `passwordUpdatedAt`) VALUES ($values '$uid', '$currentTime', '$currentTime');";
        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("DB Error", 1);
        }
    }
    private function _signIn(string $key, string $value, string $password = null, array $deviceJson = null, string $countryCode = null)
    {
        $userArray = $this->_getPrivateUser('countryCode, passwordHash, uid, disabled', $key, $value);
        if ($userArray == null) {
            throw new Exception("No user Exists with this $key", 1);
        } elseif ($key !== 'uid' && $countryCode != null && $userArray['countryCode'] !== $countryCode) {
            throw new Exception("Incorrect country code", 1);
        } elseif ($key !== 'uid' && !password_verify($password, $userArray['passwordHash'])) {
            throw new Exception("Incorrect Password", 1);
        } elseif ($userArray['disabled'] == 1) {
            throw new Exception("This user is disabled", 1);
        } else {
            return $this->_tokenSignIn($userArray['uid'], false, $deviceJson);
        }
    }

    private function _tokenSignIn(string $uid, bool $isAnonymous, array $deviceJson = null)
    {
        $token = $this->_randomStr(self::TOKEN_LENGTH);
        $currentTime = $this->_getCurrentTimeForMySQL();
        $expirePeriod = FastAuthConstants::TOKEN_EXPIRE_PERIOD;
        $query = '';
        if ($deviceJson != null) {
            $json = json_encode($deviceJson);
            $query = "INSERT INTO `fast_auth_tokens` (`token`,`uid`, `createdAt`, `expiresIn`, `deviceJson`) VALUES
            ('$token', '$uid', '$currentTime' , '$expirePeriod', '$json')";
        } else {
            $query = "INSERT INTO `fast_auth_tokens` (`token`,`uid`, `createdAt`, `expiresIn`) VALUES
        ('$token', '$uid', '$currentTime' , '$expirePeriod')";
        }

        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("DB Error", 1);
        }
        return [
            'uid' => $uid,
            'token' => $token,
            'isAnonymous' => $isAnonymous
        ];
    }

    private function _clearOTP(int $userID, string $otp, int $for)
    {
        $otpHash = $this->_cryptOTP($otp);
        $query = "DELETE FROM `fast_auth_otps` WHERE 
        `userID` = '$userID' AND
        `otpHash` = '$otpHash' AND
        `for` = '$for'";
        mysqli_query($this->conn, $query);
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

    // ********************-*-*-*-*-*-*-*-* UTILS **********-*-*-*-*-*-*-***************

    private function _isValidTimePeriod(string $createdAt, int $expiresIn)
    {
        $time = strtotime($createdAt) + $expiresIn;
        $currentTime = time();
        if ($time > $currentTime) {
            return $time - $currentTime;
        }
        return false;
    }

    private function _cryptOTP(string $otp)
    {
        return openssl_encrypt($otp, "AES-128-ECB", "__^!@XQ@z#$&*^%%Y&$&*^__");
        // return openssl_decrypt($otpHash, "AES-128-ECB", "__^!@XQ@z#$&*^%%Y&$&*^__");
    }

    private function _getCurrentTimeForMySQL(bool $isOnlyDate = false)
    {
        if ($isOnlyDate) {
            return date('Y-m-d', time());
        }
        return date('Y-m-d H:i:s', time());
    }

    private function _filterArray($array)
    {
        $newArr = [];
        foreach ($array as $key => $value) {
            if ($value == null) {
                continue;
            }
            if ($key === 'password') {
                $key = 'passwordHash';
                $value = password_hash($value, PASSWORD_BCRYPT);
            }
            $newArr[$key] = $value;
        }
        return $newArr;
    }
    private function _randomStr(int $length)
    {
        return bin2hex(openssl_random_pseudo_bytes($length));
    }

    /* private function randStr(bool $isRefreshToken = false)
    {
        $time = time();
        $bcrypt = password_hash($time, PASSWORD_BCRYPT);
        if ($isRefreshToken) {
            $bcrypt2 = password_hash($time, PASSWORD_BCRYPT);
            return substr($bcrypt, 8, strlen($bcrypt) - 10) . substr($time, 5) . substr($bcrypt, 39) . substr($bcrypt2, 8, strlen($bcrypt));
        }
        return substr($bcrypt, 7, strlen($bcrypt) - 20) . substr($time, 5) . substr($bcrypt, 27);
    } */
    /* private function matchArray($array, $key)
    {
        $ret = false;
        foreach ($array as $value) {
            if ($key === $value) {
                $ret = true;
                break;
            }
        }
        return $ret;
    } */
    /* public function forceUpdateUser(int $userID, array $userData)
    {
        $validKeys = ['name', 'profileURL', 'extraJson'];
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
    } */
    /* public function verifyEmail(int $userID, string $otp)
    {
        if (!$this->_verifyOTP($userID, $otp, self::FOR_VERIFY_EMAIL)) {
            throw new Exception("Unknown Error occured", 1);
        }
        $this->_clearOTP($userID, $otp, self::FOR_VERIFY_EMAIL);
        return $this->forceVerifyEmail($userID);
    }
    public function verifyMobile(int $userID, string $otp)
    {
        if (!$this->_verifyOTP($userID, $otp, self::FOR_VERIFY_MOBILE)) {
            throw new Exception("Unknown Error occured", 1);
        }
        $this->_clearOTP($userID, $otp, self::FOR_VERIFY_MOBILE);
        return $this->forceVerifyMobile($userID);
    }
    public function verifyResetPassword(int $userID, string $otp)
    {
        return $this->_verifyOTP($userID, $otp, self::FOR_RESET_PASSWORD);
    } */
    /* public function resetPasswordWithOTP(int $userID, string $newPassword, string $otp)
    {
        if (!$this->_verifyOTP($userID, $otp, self::FOR_RESET_PASSWORD)) {
            throw new Exception("Unknown Error occured", 1);
        }
        $this->_clearOTP($userID, $otp, self::FOR_RESET_PASSWORD);
        return $this->forceResetPassword($userID, $newPassword);
    } */
    // force
    /* public function forceVerifyEmail(int $userID)
    {
        return $this->_updateUser($userID, ['emailVerified' => true]);
    }
    // force
    public function forceVerifyMobile(int $userID)
    {
        return $this->_updateUser($userID, ['mobileVerified' => true]);
    } */
    /* private function parseUser(array $userArray)
    {
        return $userArray;
    } */
    // ************-*----------------************* OTP Functions ****************************----------

    /* public function getOtpToResetPassword(int $userID)
    {

        $userData = $this->_getPrivateUser('disabled', 'uid', $userID);
        if ($userData['disabled'] == 1) {
            throw new Exception("This user is disabled", 1);
        }
        // todo any extra condition here
        return $this->_generateOTP($userID, self::FOR_RESET_PASSWORD);
    } */
    /* private function _verifyOTP(int $userID, string $otp, int $for)
    {
        $otpHash = $this->_cryptOTP($otp);
        $query = "SELECT `createdAt` FROM `fast_auth_otps` WHERE 
        `userID` = '$userID' AND
        `otpHash` = '$otpHash' AND
        `for` = '$for'";
        $res = mysqli_query($this->conn, $query);
        if (!mysqli_num_rows($res)) {
            throw new Exception("Invalid OTP", 1);
        }
        if ($row = mysqli_fetch_assoc($res)) {
            if (!$this->_isValidTimePeriod($row['createdAt'], FastAuthConstants::OTP_EXPIRES_IN)) {
                throw new Exception("Timeout! OTP Expires", 1);
            }
            return true;
        } else {
            throw new Exception("DB Error", 1);
        }
    } */
    /* public function getOtpToVerifyEmail(int $userID)
    {
        $userData = $this->_getPrivateUser('disabled', 'uid', $userID);
        if ($userData['disabled'] == 1) {
            throw new Exception("This user is disabled", 1);
        }
        return $this->_generateOTP($userID, self::FOR_VERIFY_EMAIL);
    } */

    /* public function getOtpToVerifyMobile(int $userID)
    {
        return $this->_generateOTP($userID, self::FOR_VERIFY_MOBILE);
    } */

    /* public function getOtpToRegisterUser(int $userID)
    {
        return $this->_generateOTP($userID, self::FOR_VERIFY_CREATED_ACCOUNT);
    } */

    /* public function verifyRegisterUser(int $userID, string $otp)
    {
        $this->_verifyOTP($userID, $otp, self::FOR_VERIFY_CREATED_ACCOUNT);
        $this->_clearOTP($userID, $otp, self::FOR_VERIFY_CREATED_ACCOUNT);
        return $this->_updateUser($userID, ['signedType' => self::REGISTERED]);
    } */

    // if (!$this->_isUserExist('uid', $userID)) {
    // throw new Exception("No user exist with this userID or user is not verified", 1);
    // }
    /* private function _generateOTP(int $userID, int $for)
    {
        $otp = $this->_generateRandomOTP();
        $otpHash = $this->_cryptOTP($otp);
        $currentTime = $this->_getCurrentTimeForMySQL();

        $query = "INSERT INTO `fast_auth_otps` (`userID`,`otpHash`,`for`,`createdAt`) VALUES
        ('$userID', '$otpHash', '$for', '$currentTime')";

        if (!mysqli_query($this->conn, $query)) {
            throw new Exception("Error in generating OTP", 1);
        }
        return $otp;
    } */
}
