<?php
/*
Fast-Auth 
Version: 0.8 Beta
Developer: Shubham Gupta
Licence: MIT
Last Updated: 25 April, 2021 at 10:27 AM UTC +5:30
*/
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

    public const D_ERROR_MYSQLI_QUERY_MSG = 'Query Error';
    public const D_ERROR_MYSQLI_CONNECT_MSG = 'Connection Error';
    public const D_ERROR_UNKNOWN_MSG = 'Unknown Error';

    private const ERROR_MSG = 'Fast-Auth Error';
    private const ERROR_EMAIL_ALREADY_EXISTS_MSG = 'A user alerady exists with same email';
    private const ERROR_MOBILE_ALREADY_EXISTS_MSG = 'A user alerady exists with same mobile';
    private const ERROR_OTP_INVALID_MSG = 'Invalid OTP';
    private const ERROR_KEY_INVALID_MSG = 'Invalid Key';
    private const ERROR_KEY_EXPIRED_MSG = 'Timeout! Key Expired';
    private const ERROR_OTP_GET_ATTEMPTS_MSG = 'You reach the attempt\'s for this key';
    private const ERROR_PASSWORD_INCORRECT_MSG = 'Incorrect Password';
    private const ERROR_TOKEN_INVALID_MSG = 'Invalid Token';
    private const ERROR_TOKEN_EXPIRED_MSG = 'Timeout! Token Expired';
    private const ERROR_TOKEN_DISABLED_MSG = 'Token Disabled';
    private const ERROR_USER_NOT_EXIST_MSG = 'No user Exist';
    private const ERROR_USER_DISABLED_MSG = 'User Disabled';

    public const ERROR_CODE = 30;
    public const ERROR_EMAIL_ALREADY_EXISTS_CODE = 31;
    public const ERROR_MOBILE_ALREADY_EXISTS_CODE = 32;
    public const ERROR_OTP_GET_ATTEMPTS_CODE = 38;
    public const ERROR_OTP_INVALID_CODE = 34;
    public const ERROR_KEY_INVALID_CODE = 36;
    public const ERROR_KEY_EXPIRED_CODE = 37;
    public const ERROR_PASSWORD_INCORRECT_CODE = 40;
    public const ERROR_TOKEN_INVALID_CODE = 41;
    public const ERROR_TOKEN_EXPIRED_CODE = 42;
    public const ERROR_TOKEN_DISABLED_CODE = 43;
    public const ERROR_USER_NOT_EXIST_CODE = 44;
    public const ERROR_USER_DISABLED_CODE = 45;


    private function _setOptions(array $options = null)
    {
        $this->otpLength = 6;
        $this->otpCharacters = '0123456789';
        $this->keyExpiresIn = 3600;
        $this->tokenExpirePeriod = 2419200;
        $this->getOtpAttempts = 3;
        if ($options != null) {
            if (isset($options['otpLength']))
                $this->otpLength = $options['otpLength'];
            if (isset($options['otpCharacters']))
                $this->otpCharacters = $options['otpCharacters'];
            if (isset($options['keyExpiresIn']))
                $this->keyExpiresIn = $options['keyExpiresIn'];
            if (isset($options['tokenExpirePeriod']))
                $this->tokenExpirePeriod = $options['tokenExpirePeriod'];
            if (isset($options['getOtpAttempts']))
                $this->getOtpAttempts = $options['getOtpAttempts'];
        }
    }

    public function __construct(mysqli $db, array $optionsArray = null)
    {
        $this->_setOptions($optionsArray);
        if ($db->connect_errno) {
            throw new Exception(self::D_ERROR_MYSQLI_CONNECT_MSG, self::ERROR_CODE);
        }
        $db->options(MYSQLI_OPT_INT_AND_FLOAT_NATIVE, TRUE);
        $this->db = $db;

        $this->initialize();
    }

    public function initialize()
    {
        $createUsersTable = "CREATE TABLE IF NOT EXISTS `fast_auth_users` (
            `uid` VARCHAR(255) NOT NULL ,
            `email` VARCHAR(255) NULL ,
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
            `otpHash` VARCHAR(255) NOT NULL ,
            `createdAt` DATETIME NOT NULL ,
            `attempts` INT(11) NOT NULL default 0,
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

        if (!$this->db->query($createTempTable)) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        if (!$this->db->query($createTokensTable)) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        if (!$this->db->query($createUsersTable)) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
    }

    public function forceNewUserWithEmail(string $email, string $password, string $name, string $profileURL = null, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
    {
        if ($this->_isUserExist('email', $email)) {
            throw new Exception(self::ERROR_EMAIL_ALREADY_EXISTS_MSG, self::ERROR_EMAIL_ALREADY_EXISTS_CODE);
        }
        if ($uid == null) {
            $uid = $this->_randomStr(self::UID_LENGTH);
        }
        if (!$isAnonymous && $this->_isUserExist('uid', $uid)) {
            throw new Exception(self::ERROR_USER_NOT_EXIST_MSG, self::ERROR_USER_NOT_EXIST_CODE);
        }
        $params = ['email' => $email];
        $params['password'] = $password;
        $params['name'] = $name;
        $params['profileURL'] = $profileURL;
        $params['extraJson'] = $extraJson;
        return $this->_insertUser($params, $uid);
    }

    public function forceNewUserWithMobile(string $mobile, string $password, string $name, string $profileURL = null, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
    {
        if ($this->_isUserExist('mobile', $mobile)) {
            throw new Exception(self::ERROR_MOBILE_ALREADY_EXISTS_MSG, self::ERROR_MOBILE_ALREADY_EXISTS_CODE);
        }
        if ($uid == null) {
            $uid = $this->_randomStr(self::UID_LENGTH);
        }
        if (!$isAnonymous && $this->_isUserExist('uid', $uid)) {
            throw new Exception(self::ERROR_USER_NOT_EXIST_MSG, self::ERROR_USER_NOT_EXIST_CODE);
        }
        $params = ['mobile' => $mobile];
        $params['password'] = $password;
        $params['name'] = $name;
        $params['profileURL'] = $profileURL;
        $params['extraJson'] = $extraJson;
        return $this->_insertUser($params, $uid);
    }

    public function requestNewUserWithEmail(string $email, string $password, string $name, string $profileURL = null, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
    {
        if ($this->_isUserExist('email', $email)) {
            throw new Exception(self::ERROR_EMAIL_ALREADY_EXISTS_MSG, self::ERROR_EMAIL_ALREADY_EXISTS_CODE);
        }
        return $this->_newTempUser(['email' => $email], $password, $name, $profileURL, $extraJson, $uid, $isAnonymous);
    }
    public function requestNewUserWithMobile(string $mobile, string $password, string $name, string $profileURL = null, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
    {
        if ($this->_isUserExist('mobile', $mobile)) {
            throw new Exception(self::ERROR_MOBILE_ALREADY_EXISTS_MSG, self::ERROR_MOBILE_ALREADY_EXISTS_CODE);
        }
        return $this->_newTempUser(['mobile' => $mobile], $password, $name, $profileURL, $extraJson, $uid, $isAnonymous);
    }

    public function getOTP(string $key)
    {
        $keyData = $this->_getKeyData($key, '*');

        if (!$this->_isValidTimePeriod($keyData['createdAt'], $this->keyExpiresIn)) {
            throw new Exception(self::ERROR_KEY_EXPIRED_MSG, self::ERROR_KEY_EXPIRED_CODE);
        }
        $attempts = $keyData['attempts'] + 1;

        if ($attempts > $this->getOtpAttempts) {
            throw new Exception(self::ERROR_OTP_GET_ATTEMPTS_MSG, self::ERROR_OTP_GET_ATTEMPTS_CODE);
        }
        $data = (array)json_decode($keyData['data']);

        $sendTo = '';
        $sendType = '';
        if (isset($data['mobile'])) {
            $sendTo = $data['mobile'];
            $sendType = 'mobile';
        } elseif (isset($data['email'])) {
            $sendTo = $data['email'];
            $sendType = 'email';
        } else {
            throw new Exception(self::D_ERROR_UNKNOWN_MSG, self::ERROR_CODE);
        }
        $qz = "UPDATE `fast_auth_temp` SET attempts = $attempts WHERE `key` = '$key'";
        $this->db->query($qz);

        return [
            'otp' => $this->_decryptOTP($keyData['otpHash']),
            'case' => $keyData['case'],
            'sendTo' => $sendTo,
            'name' => $data['name'],
            'sendType' => $sendType
        ];
    }

    public function verifyOTP(string $key, string $otp)
    {
        $otpHash = $this->_cryptOTP($otp);
        $keyData = $this->_getKeyData($key, 'createdAt, otpHash');

        if (!$this->_isValidTimePeriod($keyData['createdAt'], $this->keyExpiresIn)) {
            throw new Exception(self::ERROR_KEY_EXPIRED_MSG, self::ERROR_KEY_EXPIRED_CODE);
        }
        if ($otpHash !== $keyData['otpHash']) {
            throw new Exception(self::ERROR_OTP_INVALID_MSG, self::ERROR_OTP_INVALID_CODE);
        }
        return $this->_handleVerifySuccess($key);
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
    public function signInWithMobileAndPassword(string $mobile, string $password, array $deviceJson = null)
    {
        return $this->_signIn('mobile', $mobile, $password, $deviceJson);
    }
    public function signInWithUidAndPassword(string $uid, string $password, array $deviceJson = null)
    {
        return $this->_signIn('uid', $uid, $password, $deviceJson);
    }
    public function forceSignIn(string $uid, array $deviceJson = null)
    {
        return $this->_signIn('uid', $uid, null, $deviceJson);
    }

    // ***********5*885*ad5sff*8f*a/8d*f/---------GET USER --------asdfa46546****asdf*a*dsf**adsf********
    public function getUser(string $uid)
    {
        return $this->_getPrivateUser('*', 'uid', $uid);
    }
    public function getExtraJson(string $uid)
    {
        return $this->_getPrivateUser('extraJson', 'uid', $uid);
    }
    public function isValidUser(string $uid)
    {
        return $this->_isUserExist('uid', $uid);
    }
    public function getUserByMobileNumber(string $mobile)
    {
        return $this->_getPrivateUser('*', 'mobile', $mobile);
    }
    public function getUserByEmail(string $email)
    {
        return $this->_getPrivateUser('*', 'email', $email);
    }

    public function getUsersCount()
    {
        $query = "SELECT count(*) FROM `fast_auth_users`";
        $res = $this->db->query($query);
        if (!$res) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        if ($row = $res->fetch_assoc()) {
            return $row['count(*)'];
        } else {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
    }
    public function getPagesCount(int $usersCount, int $usersPerPage = 20)
    {
        return ceil($usersCount / $usersPerPage);
    }



    public function listUsers(int $page = 1, int $usersPerPage = 20, string $orderBy = 'createdAt DESC')
    {
        $offset = ($page - 1) * $usersPerPage;
        $query = "SELECT * FROM `fast_auth_users` ORDER BY $orderBy LIMIT $offset, $usersPerPage";
        $res = $this->db->query($query);
        if (!$res) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        $array = [];
        while ($row = $res->fetch_assoc()) {
            $array[] = $row;
        }
        return $array;
    }
    // *************************************** User Edits ***********-******-*-*--*-**********

    public function forceUpdateMobile(string $uid, string $newMobile)
    {
        if ($this->_isUserExist('mobile', $newMobile)) {
            throw new Exception(self::ERROR_MOBILE_ALREADY_EXISTS_MSG, self::ERROR_MOBILE_ALREADY_EXISTS_CODE);
        }
        $this->_updateUser(['mobile' => $newMobile], $uid);
    }
    public function forceUpdateEmail(string $uid, string $newEmail)
    {
        if ($this->_isUserExist('email', $newEmail)) {
            throw new Exception(self::ERROR_EMAIL_ALREADY_EXISTS_MSG, self::ERROR_EMAIL_ALREADY_EXISTS_CODE);
        }
        $this->_updateUser(['email' => $newEmail], $uid);
    }

    public function requestUpdateMobile(string $uid, string $newMobile)
    {
        if ($this->_isUserExist('mobile', $newMobile)) {
            throw new Exception(self::ERROR_MOBILE_ALREADY_EXISTS_MSG, self::ERROR_MOBILE_ALREADY_EXISTS_CODE);
        }
        $row = $this->_getPrivateUser('name', 'uid', $uid);
        return $this->_insertTemp($uid, self::CASE_UPDATE_MOBILE, ['mobile' => $newMobile, 'name' => $row['name']], true);
    }

    public function requestUpdateEmail(string $uid, string $newEmail)
    {
        if ($this->_isUserExist('email', $newEmail)) {
            throw new Exception(self::ERROR_EMAIL_ALREADY_EXISTS_MSG, self::ERROR_EMAIL_ALREADY_EXISTS_CODE);
        }
        $row = $this->_getPrivateUser('name', 'uid', $uid);
        return $this->_insertTemp($uid, self::CASE_UPDATE_EMAIL, ['email' => $newEmail, 'name' => $row['name']], true);
    }
    public function requestUpdatePasswordWithEmail(string $email)
    {
        $row = $this->_getPrivateUser('uid, name', 'email', $email);
        return $this->_insertTemp($row['uid'], self::CASE_UPDATE_PASSWORD, ['email' => $email, 'name' => $row['name']], true);
    }

    public function requestUpdatePasswordWithMobile(string $mobile)
    {
        $row = $this->_getPrivateUser('uid, name', 'mobile', $mobile);
        return $this->_insertTemp($row['uid'], self::CASE_UPDATE_PASSWORD, ['mobile' => $mobile, 'name' => $row['name']], true);
    }


    public function updatePassword(string $passwordUpdateKey, string $newPassword)
    {
        $row = $this->_getKeyData($passwordUpdateKey, 'uid, createdAt');
        if (!$this->_isValidTimePeriod($row['createdAt'], $this->keyExpiresIn)) {
            throw new Exception(self::ERROR_KEY_EXPIRED_MSG, self::ERROR_KEY_EXPIRED_CODE);
        }
        $this->_clearTable('fast_auth_temp', 'key', $passwordUpdateKey);
        return $this->_updateUser([
            'passwordHash' => password_hash($newPassword, PASSWORD_BCRYPT),
            'passwordUpdatedAt' => $this->_getCurrentTimeForMySQL()
        ], $row['uid']);
    }

    public function updatePasswordWithCurrentPassword(string $uid, string $currentPassword, string $newPassword)
    {
        $row = $this->_getPrivateUser('passwordHash', 'uid', $uid);
        if (!password_verify($currentPassword, $row['passwordHash'])) {
            throw new Exception(self::ERROR_PASSWORD_INCORRECT_MSG, self::ERROR_PASSWORD_INCORRECT_CODE);
        }
        return $this->_updateUser([
            'passwordHash' => password_hash($newPassword, PASSWORD_BCRYPT),
            'passwordUpdatedAt' => $this->_getCurrentTimeForMySQL()
        ], $uid);
    }

    // force
    public function updateName(string $uid, string $newName)
    {
        return $this->_updateUser(['name' => $newName], $uid);
    }
    public function updateExtraJson(string $uid, array $extraJson = null)
    {
        if ($extraJson == null) {
            return $this->_updateUser(['extraJson' => null], $uid);
        }
        return $this->_updateUser(['extraJson' => json_encode($extraJson)], $uid);
    }
    public function updateProfileURL(string $uid, string $newProfileURL)
    {
        return $this->_updateUser(['profileURL' => $newProfileURL], $uid);
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

    public function verifyToken(string $token)
    {
        $query = "SELECT * FROM `fast_auth_tokens` WHERE `token` = '$token'";
        $res = $this->db->query($query);
        if (!$res) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        if (!$res->num_rows) {
            throw new Exception(self::ERROR_TOKEN_INVALID_MSG, self::ERROR_TOKEN_INVALID_CODE);
        }
        if ($row = $res->fetch_assoc()) {
            $timeGap = $this->_isValidTimePeriod($row['createdAt'], $row['expiresIn']);
            if (!$timeGap) {
                throw new Exception(self::ERROR_TOKEN_EXPIRED_MSG, self::ERROR_TOKEN_EXPIRED_CODE);
            } elseif ($row['disabled']) {
                throw new Exception(self::ERROR_TOKEN_DISABLED_MSG, self::ERROR_TOKEN_DISABLED_CODE);
            } else {
                $timeGap = $timeGap + $this->tokenExpirePeriod;
                $q2 = "UPDATE `fast_auth_tokens` SET `expiresIn` = '$timeGap' WHERE `token` = '$token'";
                $this->db->query($q2);
                return $row['uid'];
            }
        } else {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
    }

    public function signOutAllDevices(string $uid, string $exceptToken = null)
    {
        $query = "UPDATE `fast_auth_tokens` SET `disabled` = 1 WHERE `uid` = '$uid'";
        if ($exceptToken) {
            $query .= " AND `token` <> '$exceptToken'";
        }
        if (!$this->db->query($query)) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
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
        if (!$this->db->query($query)) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        return true;
    }

    private function _getPrivateUser(string $columns, string $key, string $value)
    {
        $query = "SELECT $columns FROM `fast_auth_users` WHERE `$key` = '$value'";
        $res = $this->db->query($query);
        if (!$res) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        if (!$res->num_rows) {
            throw new Exception(self::ERROR_USER_NOT_EXIST_MSG, self::ERROR_USER_NOT_EXIST_CODE);
        }
        if ($row = $res->fetch_assoc()) {
            return $row;
        } else {
            throw new Exception(self::D_ERROR_UNKNOWN_MSG, self::ERROR_CODE);
        }
    }
    private function _isUserExist(string $key, string $value)
    {
        try {
            $this->_getPrivateUser('uid', $key, $value);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    private function _handleVerifySuccess(string $key)
    {
        $row = $this->_getKeyData($key, '*');
        // todo change * to column names
        $data = (array) json_decode($row['data']);
        $this->_clearTable('fast_auth_temp', 'key', $key);
        switch ($row['case']) {
            case self::CASE_NEW_USER:
                $this->_insertUser($data, $row['uid']);
                return ['case' => $row['case'], 'uid' => $row['uid']];
                break;
            case self::CASE_UPDATE_PASSWORD:
                $passwordUpdateKey = $this->_insertTemp($row['uid'], self::CASE_PRIVATE_PASSWORD_UPDATE, null, true);
                return ['case' => $row['case'], 'passwordUpdateKey' => $passwordUpdateKey];
                break;
            case self::CASE_UPDATE_EMAIL:
            case self::CASE_UPDATE_MOBILE:
                $this->_updateUser($data, $row['uid']);
                return ['case' => $row['case']];
                break;
            default:
                throw new Exception(self::D_ERROR_UNKNOWN_MSG, self::ERROR_CODE);
                break;
        }
    }
    // todo forceCreateUserWith* Function
    private function _newTempUser(array $params, string $password, string $name, string $profileURL = null, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
    {
        $params['password'] = $password;
        $params['name'] = $name;
        $params['profileURL'] = $profileURL;
        $params['extraJson'] = $extraJson;
        if ($uid == null) {
            $uid = $this->_randomStr(self::UID_LENGTH);
        }
        if (!$isAnonymous && $this->_isUserExist('uid', $uid)) {
            throw new Exception(self::ERROR_USER_NOT_EXIST_MSG, self::ERROR_USER_NOT_EXIST_CODE);
        }
        return $this->_insertTemp($uid, self::CASE_NEW_USER, $params);
    }

    private function _insertTemp(string $uid, int $case, array $params = null, bool $checkIsUidExist = false)
    {
        if ($checkIsUidExist && !$this->_isUserExist('uid', $uid)) { //check krna hai aur user exist nahi karta to
            throw new Exception(self::ERROR_USER_NOT_EXIST_MSG, self::ERROR_USER_NOT_EXIST_CODE);
        }
        $key = $this->_randomStr(self::KEY_LENGTH);
        $currentDate = $this->_getCurrentTimeForMySQL();

        $query = '';
        if ($params != null) {
            $data = json_encode($this->_filterArray($params));
            $otp = $this->_generateRandomOTP();
            $otpHash = $this->_cryptOTP($otp);
            $query = "INSERT INTO `fast_auth_temp` (`key`,`uid`,`otpHash`,`createdAt`,`case`,`data`) VALUES ('$key', '$uid', '$otpHash', '$currentDate', '$case', '$data');";
        } else {
            $query = "INSERT INTO `fast_auth_temp` (`key`,`uid`,`createdAt`,`case`) VALUES ('$key', '$uid', '$currentDate', '$case');";
        }

        if (!$this->db->query($query)) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        return $key;
    }
    private function _getKeyData(string $key, string $columns = null)
    {
        if ($columns === null) {
            $columns = '`case`';
        }
        $query = "SELECT $columns FROM `fast_auth_temp` WHERE `key` = '$key'";
        $res = $this->db->query($query);
        if (!$res) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        if (!$res->num_rows) {
            throw new Exception(self::ERROR_KEY_INVALID_MSG, self::ERROR_KEY_INVALID_CODE);
        }
        if ($row = $res->fetch_assoc()) {
            return $row;
        } else {
            throw new Exception(self::D_ERROR_UNKNOWN_MSG, self::ERROR_CODE);
        }
    }

    private function _insertUser(array $params, string $uid)
    {
        if (isset($params['mobile']) && $this->_isUserExist('mobile', $params['mobile'])) {
            throw new Exception(self::ERROR_MOBILE_ALREADY_EXISTS_MSG, self::ERROR_MOBILE_ALREADY_EXISTS_CODE);
        } elseif (isset($params['email']) && $this->_isUserExist('email', $params['email'])) {
            throw new Exception(self::ERROR_EMAIL_ALREADY_EXISTS_MSG, self::ERROR_EMAIL_ALREADY_EXISTS_CODE);
        }

        // unset($params['case']);

        $colums = "";
        $values = "";
        foreach ($params as $key => $value) {
            if ($value == null) {
                continue;
            }
            $colums .= "`$key`,";
            if ($key === 'extraJson') {
                $value = json_encode($value);
            }
            $values .= "'$value',";
        }
        $currentTime = $this->_getCurrentTimeForMySQL();
        $query = "INSERT INTO `fast_auth_users` ($colums `uid`, `createdAt`, `passwordUpdatedAt`) VALUES 
        ($values '$uid', '$currentTime', '$currentTime');";
        if (!$this->db->query($query)) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
    }
    private function _signIn(string $key, string $value, string $password = null, array $deviceJson = null)
    {
        $userArray = $this->_getPrivateUser('passwordHash, uid, disabled', $key, $value);
        if ($userArray == null) {
            throw new Exception(self::ERROR_USER_NOT_EXIST_MSG, self::ERROR_USER_NOT_EXIST_CODE);
        } elseif ($key !== 'uid' && !password_verify($password, $userArray['passwordHash'])) {
            throw new Exception(self::ERROR_PASSWORD_INCORRECT_MSG, self::ERROR_PASSWORD_INCORRECT_CODE);
        } elseif ($userArray['disabled'] == 1) {
            throw new Exception(self::ERROR_USER_DISABLED_MSG, self::ERROR_USER_DISABLED_CODE);
        } else {
            return $this->_tokenSignIn($userArray['uid'], false, $deviceJson);
        }
    }

    private function _tokenSignIn(string $uid, bool $isAnonymous, array $deviceJson = null)
    {
        $token = $this->_randomStr(self::TOKEN_LENGTH);
        $currentTime = $this->_getCurrentTimeForMySQL();
        $expirePeriod = $this->tokenExpirePeriod;
        $query = '';
        if ($deviceJson != null) {
            $json = json_encode($deviceJson);
            $query = "INSERT INTO `fast_auth_tokens` (`token`,`uid`, `createdAt`, `expiresIn`, `deviceJson`) VALUES
            ('$token', '$uid', '$currentTime' , '$expirePeriod', '$json')";
        } else {
            $query = "INSERT INTO `fast_auth_tokens` (`token`,`uid`, `createdAt`, `expiresIn`) VALUES
        ('$token', '$uid', '$currentTime' , '$expirePeriod')";
        }

        if (!$this->db->query($query)) {
            throw new Exception(self::D_ERROR_MYSQLI_QUERY_MSG, self::ERROR_CODE);
        }
        return [
            'uid' => $uid,
            'token' => $token,
            'isAnonymous' => $isAnonymous
        ];
    }

    private function _clearTable(string $tableName, string $column, string $value)
    {
        $query = "DELETE FROM `$tableName` WHERE `$column` = '$value'";
        $this->db->query($query);
    }

    private function _generateRandomOTP()
    {
        $charactersLength = strlen($this->otpCharacters);
        $randomString = '';
        for ($i = 0; $i < $this->otpLength; $i++) {
            $randomString .= $this->otpCharacters[rand(0, $charactersLength - 1)];
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
    }

    private function _decryptOTP(string $otpHash)
    {
        return openssl_decrypt($otpHash, "AES-128-ECB", "__^!@XQ@z#$&*^%%Y&$&*^__");
    }

    private function _getCurrentTimeForMySQL()
    {
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
}
