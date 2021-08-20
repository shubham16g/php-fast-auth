<?php
/*
PHPFastAuth
Version: 0.9.1 Beta
Developer: Shubham Gupta
Licence: MIT
Last Updated: 20 Aug, 2021 at 9:42 PM UTC +5:30
*/

namespace {

    use PHPFastAuth\Options;

    class PHPFastAuth
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


        private function _setOptions(Options $option = null)
        {
            if ($option == null)
                $option = new Options();
            $this->OTPLength = $option->OTPLength;
            $this->OTPCharacters = $option->OTPCharacters;
            $this->keyExpiresIn = $option->keyExpiresIn;
            $this->tokenExpirePeriod = $option->tokenExpirePeriod;
            $this->decodeOTPAttempts = $option->decodeOTPAttempts;
        }

        public function __construct(mysqli $db, Options $option = null)
        {
            $this->_setOptions($option);
            if ($db->connect_errno) {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_CONNECT();
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
            `disabled` TINYINT(1) NOT NULL default 0 ,
            `type` TINYINT(1) NOT NULL default 0 ,
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
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$this->db->query($createTokensTable)) {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$this->db->query($createUsersTable)) {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
        }

        public function forceNewUserWithEmail(string $email, string $password, string $name, int $type = 0, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
        {
            if ($this->_isUserExist('email', $email, $type)) {
                throw PHPFastAuth\Errors::ERROR_EMAIL_ALREADY_EXISTS();
            }
            if ($uid == null) {
                $uid = $this->_randomStr(self::UID_LENGTH);
            }
            if (!$isAnonymous && $this->_isUserExistWithUID($uid)) {
                throw PHPFastAuth\Errors::ERROR_USER_NOT_EXIST();
            }
            $params = ['email' => $email];
            $params['password'] = $password;
            $params['name'] = $name;
            $params['type'] = $type;
            $params['extraJson'] = $extraJson;
            return $this->_insertUser($params, $uid);
        }

        public function forceNewUserWithMobile(string $mobile, string $password, string $name, int $type = 0, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
        {
            if ($this->_isUserExist('mobile', $mobile, $type)) {
                throw PHPFastAuth\Errors::ERROR_MOBILE_ALREADY_EXISTS();
            }
            if ($uid == null) {
                $uid = $this->_randomStr(self::UID_LENGTH);
            }
            if (!$isAnonymous && $this->_isUserExistWithUID($uid)) {
                throw PHPFastAuth\Errors::ERROR_USER_NOT_EXIST();
            }
            $params = ['mobile' => $mobile];
            $params['password'] = $password;
            $params['name'] = $name;
            $params['type'] = $type;
            $params['extraJson'] = $extraJson;
            return $this->_insertUser($params, $uid);
        }

        public function requestNewUserWithEmail(string $email, string $password, string $name, int $type = 0, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
        {
            if ($this->_isUserExist('email', $email, $type)) {
                throw PHPFastAuth\Errors::ERROR_EMAIL_ALREADY_EXISTS();
            }
            return $this->_newTempUser(['email' => $email, 'type' => $type], $password, $name, $extraJson, $uid, $isAnonymous);
        }
        public function requestNewUserWithMobile(string $mobile, string $password, string $name, int $type = 0, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
        {
            if ($this->_isUserExist('mobile', $mobile, $type)) {
                throw PHPFastAuth\Errors::ERROR_MOBILE_ALREADY_EXISTS();
            }
            return $this->_newTempUser(['mobile' => $mobile, 'type' => $type], $password, $name, $extraJson, $uid, $isAnonymous);
        }

        public function getOTP(string $key)
        {
            $keyData = $this->_getKeyData($key, '*');

            if (!$this->_isValidTimePeriod($keyData['createdAt'], $this->keyExpiresIn)) {
                throw PHPFastAuth\Errors::ERROR_KEY_EXPIRED();
            }
            $attempts = $keyData['attempts'] + 1;

            if ($attempts > $this->decodeOTPAttempts) {
                throw PHPFastAuth\Errors::ERROR_OTP_GET_ATTEMPTS();
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
                throw PHPFastAuth\Errors::D_ERROR_UNKNOWN();
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
                throw PHPFastAuth\Errors::ERROR_KEY_EXPIRED();
            }
            if ($otpHash !== $keyData['otpHash']) {
                throw PHPFastAuth\Errors::ERROR_OTP_INVALID();
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
        public function signInWithEmailAndPassword(string $email, string $password, int $type = 0, array $deviceJson = null)
        {
            return $this->_signIn('email', $email, $type, $password, $deviceJson);
        }
        public function signInWithMobileAndPassword(string $mobile, string $password, int $type = 0, array $deviceJson = null)
        {
            return $this->_signIn('mobile', $mobile, $type, $password, $deviceJson);
        }
        public function signInWithUidAndPassword(string $uid, string $password, array $deviceJson = null)
        {
            return $this->_signIn('uid', $uid, -11, $password, $deviceJson);
        }
        public function forceSignIn(string $uid, array $deviceJson = null)
        {
            return $this->_signIn('uid', $uid, -11, null, $deviceJson);
        }

        // ***********5*885*ad5sff*8f*a/8d*f/---------GET USER --------asdfa46546****asdf*a*dsf**adsf********
        public function getUser(string $uid)
        {
            return $this->_getPrivateUserWithUID('*', $uid);
        }
        public function getExtraJson(string $uid)
        {
            return $this->_getPrivateUserWithUID('extraJson', $uid);
        }
        public function isValidUser(string $uid)
        {
            return $this->_isUserExistWithUID($uid);
        }
        public function getUserByMobileNumber(string $mobile, int $type = 0)
        {
            return $this->_getPrivateUser('*', 'mobile', $mobile, $type);
        }
        public function getUserByEmail(string $email, int $type = 0)
        {
            return $this->_getPrivateUser('*', 'email', $email, $type);
        }

        public function getUserType(string $uid)
        {
            $userArr = $this->_getPrivateUserWithUID('type', $uid);
            if ($userArr != null && sizeof($userArr) > 0) {
                return $userArr[0]['type'];
            } else {
                throw PHPFastAuth\Errors::D_ERROR_UNKNOWN();
            }
        }

        public function getUsersCount()
        {
            $query = "SELECT count(*) FROM `fast_auth_users`";
            $res = $this->db->query($query);
            if (!$res) {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            if ($row = $res->fetch_assoc()) {
                return $row['count(*)'];
            } else {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
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
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            $array = [];
            while ($row = $res->fetch_assoc()) {
                $array[] = $row;
            }
            return $array;
        }
        // *************************************** User Edits ***********-******-*-*--*-**********

        public function forceUpdateMobile(string $uid, string $newMobile, int $type = 0)
        {
            if ($this->_isUserExist('mobile', $newMobile, $type)) {
                throw PHPFastAuth\Errors::ERROR_MOBILE_ALREADY_EXISTS();
            }
            $this->_updateUser(['mobile' => $newMobile], $uid);
        }
        public function forceUpdateEmail(string $uid, string $newEmail, int $type = 0)
        {
            if ($this->_isUserExist('email', $newEmail, $type)) {
                throw PHPFastAuth\Errors::ERROR_EMAIL_ALREADY_EXISTS();
            }
            $this->_updateUser(['email' => $newEmail], $uid);
        }

        public function requestUpdateMobile(string $uid, string $newMobile, int $type = 0)
        {
            if ($this->_isUserExist('mobile', $newMobile, $type)) {
                throw PHPFastAuth\Errors::ERROR_MOBILE_ALREADY_EXISTS();
            }
            $row = $this->_getPrivateUserWithUID('name', $uid);
            return $this->_insertTemp($uid, self::CASE_UPDATE_MOBILE, ['mobile' => $newMobile, 'name' => $row['name']], true);
        }

        public function requestUpdateEmail(string $uid, string $newEmail, int $type = 0)
        {
            if ($this->_isUserExist('email', $newEmail, $type)) {
                throw PHPFastAuth\Errors::ERROR_EMAIL_ALREADY_EXISTS();
            }
            $row = $this->_getPrivateUserWithUID('name', $uid);
            return $this->_insertTemp($uid, self::CASE_UPDATE_EMAIL, ['email' => $newEmail, 'name' => $row['name']], true);
        }
        public function requestUpdatePasswordWithEmail(string $email, int $type = 0)
        {
            $row = $this->_getPrivateUser('uid, name', 'email', $email, $type);
            return $this->_insertTemp($row['uid'], self::CASE_UPDATE_PASSWORD, ['email' => $email, 'name' => $row['name']], true);
        }

        public function requestUpdatePasswordWithMobile(string $mobile, int $type = 0)
        {
            $row = $this->_getPrivateUser('uid, name', 'mobile', $mobile, $type);
            return $this->_insertTemp($row['uid'], self::CASE_UPDATE_PASSWORD, ['mobile' => $mobile, 'name' => $row['name']], true);
        }


        public function updatePassword(string $passwordUpdateKey, string $newPassword)
        {
            $row = $this->_getKeyData($passwordUpdateKey, 'uid, createdAt');
            if (!$this->_isValidTimePeriod($row['createdAt'], $this->keyExpiresIn)) {
                throw PHPFastAuth\Errors::ERROR_KEY_EXPIRED();
            }
            $this->_clearTable('fast_auth_temp', 'key', $passwordUpdateKey);
            return $this->_updateUser([
                'passwordHash' => password_hash($newPassword, PASSWORD_BCRYPT),
                'passwordUpdatedAt' => $this->_getCurrentTimeForMySQL()
            ], $row['uid']);
        }

        public function updatePasswordWithCurrentPassword(string $uid, string $currentPassword, string $newPassword)
        {
            $row = $this->_getPrivateUserWithUID('passwordHash', $uid);
            if (!password_verify($currentPassword, $row['passwordHash'])) {
                throw PHPFastAuth\Errors::ERROR_PASSWORD_INCORRECT();
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
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$res->num_rows) {
                throw PHPFastAuth\Errors::ERROR_TOKEN_INVALID();
            }
            if ($row = $res->fetch_assoc()) {
                $timeGap = $this->_isValidTimePeriod($row['createdAt'], $row['expiresIn']);
                if (!$timeGap) {
                    throw PHPFastAuth\Errors::ERROR_TOKEN_EXPIRED();
                } elseif ($row['disabled']) {
                    throw PHPFastAuth\Errors::ERROR_TOKEN_DISABLED();
                } else {
                    $timeGap = $timeGap + $this->tokenExpirePeriod;
                    $q2 = "UPDATE `fast_auth_tokens` SET `expiresIn` = '$timeGap' WHERE `token` = '$token'";
                    $this->db->query($q2);
                    return $row['uid'];
                }
            } else {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
        }

        public function signOutAllDevices(string $uid, string $exceptToken = null)
        {
            $query = "UPDATE `fast_auth_tokens` SET `disabled` = 1 WHERE `uid` = '$uid'";
            if ($exceptToken) {
                $query .= " AND `token` <> '$exceptToken'";
            }
            if (!$this->db->query($query)) {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
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
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            return true;
        }

        private function _getPrivateUserWithUID(string $columns, string $uid)
        {
            $query = "SELECT $columns FROM `fast_auth_users` WHERE `uid` = '$uid'";
            $res = $this->db->query($query);
            if (!$res) {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$res->num_rows) {
                throw PHPFastAuth\Errors::ERROR_USER_NOT_EXIST();
            }
            if ($row = $res->fetch_assoc()) {
                return $row;
            } else {
                throw PHPFastAuth\Errors::D_ERROR_UNKNOWN();
            }
        }

        private function _getPrivateUser(string $columns, string $key, string $value, int $type)
        {
            $query = "SELECT $columns FROM `fast_auth_users` WHERE `$key` = '$value' AND `type` = $type";
            $res = $this->db->query($query);
            if (!$res) {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$res->num_rows) {
                throw PHPFastAuth\Errors::ERROR_USER_NOT_EXIST();
            }
            if ($row = $res->fetch_assoc()) {
                return $row;
            } else {
                throw PHPFastAuth\Errors::D_ERROR_UNKNOWN();
            }
        }
        private function _isUserExist(string $key, string $value, int $type)
        {
            try {
                $this->_getPrivateUser('uid', $key, $value, $type);
                return true;
            } catch (\Exception $e) {
                return false;
            }
        }
        private function _isUserExistWithUID(string $uid)
        {
            try {
                $this->_getPrivateUserWithUID('uid', $uid);
                return true;
            } catch (\Exception $e) {
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
                    throw PHPFastAuth\Errors::D_ERROR_UNKNOWN();
                    break;
            }
        }
        // todo forceCreateUserWith* Function
        private function _newTempUser(array $params, string $password, string $name, array $extraJson = null, string $uid = null, bool $isAnonymous = false)
        {
            $params['password'] = $password;
            $params['name'] = $name;
            $params['extraJson'] = $extraJson;
            if ($uid == null) {
                $uid = $this->_randomStr(self::UID_LENGTH);
            }
            if (!$isAnonymous && $this->_isUserExistWithUID($uid)) {
                throw PHPFastAuth\Errors::ERROR_USER_NOT_EXIST();
            }
            return $this->_insertTemp($uid, self::CASE_NEW_USER, $params);
        }

        private function _insertTemp(string $uid, int $case, array $params = null, bool $checkIsUidExist = false)
        {
            if ($checkIsUidExist && !$this->_isUserExistWithUID($uid)) { //check krna hai aur user exist nahi karta to
                throw PHPFastAuth\Errors::ERROR_USER_NOT_EXIST();
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
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            return $key;
        }
        private function _getKeyData(string $key, string $columns)
        {
            if ($columns === null) {
                $columns = '`case`';
            }
            $query = "SELECT $columns FROM `fast_auth_temp` WHERE `key` = '$key'";
            $res = $this->db->query($query);
            if (!$res) {
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$res->num_rows) {
                throw PHPFastAuth\Errors::ERROR_KEY_INVALID();
            }
            if ($row = $res->fetch_assoc()) {
                return $row;
            } else {
                throw PHPFastAuth\Errors::D_ERROR_UNKNOWN();
            }
        }

        private function _insertUser(array $params, string $uid)
        {
            if (isset($params['mobile']) && $this->_isUserExist('mobile', $params['mobile'], $params['type'])) {
                throw PHPFastAuth\Errors::ERROR_MOBILE_ALREADY_EXISTS();
            } elseif (isset($params['email']) && $this->_isUserExist('email', $params['email'], $params['type'])) {
                throw PHPFastAuth\Errors::ERROR_EMAIL_ALREADY_EXISTS();
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
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
            }
        }
        private function _signIn(string $key, string $value, int $type, string $password = null, array $deviceJson = null)
        {
            $userArray = null;
            if ($type == -11) {
                $userArray = $this->_getPrivateUserWithUID('passwordHash, uid, disabled', $value);
            } else {
                $userArray = $this->_getPrivateUser('passwordHash, uid, disabled', $key, $value, $type);
            }
            if ($userArray == null) {
                throw PHPFastAuth\Errors::ERROR_USER_NOT_EXIST();
            } elseif ($key !== 'uid' && !password_verify($password, $userArray['passwordHash'])) {
                throw PHPFastAuth\Errors::ERROR_PASSWORD_INCORRECT();
            } elseif ($userArray['disabled'] == 1) {
                throw PHPFastAuth\Errors::ERROR_USER_DISABLED();
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
                throw PHPFastAuth\Errors::D_ERROR_MYSQLI_QUERY();
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
            $charactersLength = strlen($this->OTPCharacters);
            $randomString = '';
            for ($i = 0; $i < $this->OTPLength; $i++) {
                $randomString .= $this->OTPCharacters[rand(0, $charactersLength - 1)];
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
                if ($value === null) {
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
}

namespace PHPFastAuth {



    class Options
    {
        public function __construct()
        {
            $this->OTPLength = 6;
            $this->OTPCharacters = '0123456789';
            $this->keyExpiresIn = 3600;
            $this->tokenExpirePeriod = 2419200;
            $this->decodeOTPAttempts = 3;
        }
        public function setOTPLength(int $OTPLength): void
        {
            $this->OTPLength = $OTPLength;
        }
        public function setOTPCharacters(string $OTPCharacters): void
        {
            $this->OTPCharacters = $OTPCharacters;
        }
        public function setKeyExpiresIn(int $keyExpiresIn): void
        {
            $this->keyExpiresIn = $keyExpiresIn;
        }
        public function setTokenExpirePeriod(int $tokenExpirePeriod): void
        {
            $this->tokenExpirePeriod = $tokenExpirePeriod;
        }
        public function setDecodeOTPAttempts(int $decodeOTPAttempts): void
        {
            $this->decodeOTPAttempts = $decodeOTPAttempts;
        }
    }

    class Errors
    {
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

        public static function D_ERROR_MYSQLI_QUERY(): \Exception
        {
            return new \Exception('Query Error', self::ERROR_CODE);
        }
        public static function D_ERROR_MYSQLI_CONNECT(): \Exception
        {
            return new \Exception('Connection Error', self::ERROR_CODE);
        }
        public static function D_ERROR_UNKNOWN(): \Exception
        {
            return new \Exception('Unknown Error', self::ERROR_CODE);
        }
        public static function ERROR(): \Exception
        {
            return new \Exception('Fast-Auth Error', self::ERROR_CODE);
        }
        public static function ERROR_EMAIL_ALREADY_EXISTS(): \Exception
        {
            return new \Exception('A user alerady exists with same email', self::ERROR_EMAIL_ALREADY_EXISTS_CODE);
        }
        public static function ERROR_MOBILE_ALREADY_EXISTS(): \Exception
        {
            return new \Exception('A user alerady exists with same mobile', self::ERROR_MOBILE_ALREADY_EXISTS_CODE);
        }
        public static function ERROR_OTP_INVALID(): \Exception
        {
            return new \Exception('Invalid OTP', self::ERROR_OTP_INVALID_CODE);
        }
        public static function ERROR_KEY_INVALID(): \Exception
        {
            return new \Exception('Invalid Key', self::ERROR_KEY_INVALID_CODE);
        }
        public static function ERROR_KEY_EXPIRED(): \Exception
        {
            return new \Exception('Timeout! Key Expired', self::ERROR_KEY_EXPIRED_CODE);
        }
        public static function ERROR_OTP_GET_ATTEMPTS(): \Exception
        {
            return new \Exception('You reach the attempt\'s for this key', self::ERROR_OTP_GET_ATTEMPTS_CODE);
        }
        public static function ERROR_PASSWORD_INCORRECT(): \Exception
        {
            return new \Exception('Incorrect Password', self::ERROR_PASSWORD_INCORRECT_CODE);
        }
        public static function ERROR_TOKEN_INVALID(): \Exception
        {
            return new \Exception('Invalid Token', self::ERROR_TOKEN_INVALID_CODE);
        }
        public static function ERROR_TOKEN_EXPIRED(): \Exception
        {
            return new \Exception('Timeout! Token Expired', self::ERROR_TOKEN_EXPIRED_CODE);
        }
        public static function ERROR_TOKEN_DISABLED(): \Exception
        {
            return new \Exception('Token Disabled', self::ERROR_TOKEN_DISABLED_CODE);
        }
        public static function ERROR_USER_NOT_EXIST(): \Exception
        {
            return new \Exception('No user Exist', self::ERROR_USER_NOT_EXIST_CODE);
        }
        public static function ERROR_USER_DISABLED(): \Exception
        {
            return new \Exception('User Disabled', self::ERROR_USER_DISABLED_CODE);
        }
    }
}
