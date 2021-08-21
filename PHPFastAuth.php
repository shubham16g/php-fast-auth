<?php
/*
PHPFastAuth
Version: 0.9.1 Beta
Developer: Shubham Gupta
Licence: MIT
Last Updated: 20 Aug, 2021 at 9:42 PM UTC +5:30
*/

namespace {

    use PHPFastAuth\_SignIn;
    use PHPFastAuth\Options;
    use PHPFastAuth\Errors;
    use PHPFastAuth\OTPData;
    use PHPFastAuth\_SignUp;
    use PHPFastAuth\SignInWithUID;
    use PHPFastAuth\Utils;

    class PHPFastAuth
    {
        const FOR_RESET_PASSWORD = 8;
        const FOR_VERIFY_EMAIL = 7;
        const FOR_VERIFY_MOBILE = 6;
        const FOR_VERIFY_CREATED_ACCOUNT = 5;

        public const CASE_NEW_USER = 5;
        public const CASE_UPDATE_MOBILE = 6;
        public const CASE_UPDATE_EMAIL = 7;
        public const CASE_UPDATE_PASSWORD = 8;
        private const CASE_PRIVATE_PASSWORD_UPDATE = 9;

        public function __construct(mysqli $db, Options $option = null)
        {
            $this->_setOptions($option);
            if ($db->connect_errno) {
                throw Errors::D_ERROR_MYSQLI_CONNECT();
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
            `extras` JSON NULL ,
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
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$this->db->query($createTokensTable)) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$this->db->query($createUsersTable)) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
        }

        // todo return type
        public function forceSignUp(_SignUp $signUp)
        {
            $params = $this->_validateSignUp($signUp);
            return $this->_insertUser($signUp->uid, $params);
        }

        public function signUpRequest(_SignUp $signUp): string
        {
            $params = $this->_validateSignUp($signUp);
            return $this->_newTempUser($signUp, $params);
        }

        private function _validateSignUp(_SignUp $signUp): array
        {
            $params = [];
            if ($signUp->mobile != null) {
                if ($this->_isUserExist('mobile', $signUp->mobile, $signUp->type))
                    throw Errors::ERROR_EMAIL_ALREADY_EXISTS();
                $params['mobile'] = $signUp->mobile;
            } elseif ($signUp->email != null) {
                if ($this->_isUserExist('email', $signUp->email, $signUp->type))
                    throw Errors::ERROR_EMAIL_ALREADY_EXISTS();
                $params['email'] = $signUp->email;
            } else {
                throw Errors::ERROR_NO_EMIAL_OR_MOBILE_PROVIDED();
            }
            if ($this->_isUserExistWithUID($signUp->uid)) {
                throw Errors::ERROR_USER_NOT_EXIST();
            }
            // todo name, password, extras
            $params['password'] = $signUp->password;
            $params['name'] = $signUp->name;
            $params['extras'] = $signUp->extras;
            $params['type'] = $signUp->type;

            return $params;
        }

        public function decodeOTP(string $key): OTPData
        {
            $keyData = $this->_getKeyData($key, '*');

            if (!Utils::_isValidTimePeriod($keyData['createdAt'], $this->keyExpiresIn)) {
                throw Errors::ERROR_KEY_EXPIRED();
            }
            $attempts = $keyData['attempts'] + 1;

            if ($attempts > $this->decodeOTPAttempts) {
                throw Errors::ERROR_OTP_GET_ATTEMPTS();
            }
            $data = (array)json_decode($keyData['data']);

            $otpData = new OTPData(Utils::_decryptOTP($keyData['otpHash']), $keyData['case'], $data['name']);

            // todo define golbal const type
            if (isset($data['mobile'])) {
                $otpData->mobile = $data['mobile'];
                $otpData->type = 'mobile';
            } elseif (isset($data['email'])) {
                $otpData->email = $data['email'];
                $otpData->type = 'email';
            } else {
                throw Errors::ERROR_NO_EMIAL_OR_MOBILE_PROVIDED();
            }
            $qz = "UPDATE `fast_auth_temp` SET attempts = $attempts WHERE `key` = '$key'";
            $this->db->query($qz);

            return $otpData;
        }

        public function verifyOTP(string $key, string $otp)
        {
            $otpHash = Utils::_cryptOTP($otp);
            $keyData = $this->_getKeyData($key, 'createdAt, otpHash');

            if (!Utils::_isValidTimePeriod($keyData['createdAt'], $this->keyExpiresIn)) {
                throw Errors::ERROR_KEY_EXPIRED();
            }
            if ($otpHash !== $keyData['otpHash']) {
                throw Errors::ERROR_OTP_INVALID();
            }
            return $this->_handleVerifySuccess($key);
        }
        private function _handleVerifySuccess(string $key)
        {
            $row = $this->_getKeyData($key, '*');
            // todo change * to column names
            $data = (array) json_decode($row['data']);
            $this->_clearTable('fast_auth_temp', 'key', $key);
            switch ($row['case']) {
                case self::CASE_NEW_USER:
                    $this->_insertUser($row['uid'], $data);
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
                    throw Errors::D_ERROR_UNKNOWN();
                    break;
            }
        }

        // **************************** SIGNIN PROCESS *-********************************----*******

        public function signInAnonymously(array $deviceJson = null)
        {
            $uid = Utils::randomUID();
            $this->_insertUser(
                $uid,
                [
                    'isAnonymous' => 1,
                ]
            );
            return $this->_tokenSignIn($uid, true, $deviceJson);
        }

        public function signIn(_SignIn $signIn)
        {
            return $this->_signIn($signIn, false);
        }

        public function signInWithoutPassword(SignInWithUID $signIn)
        {
            return $this->_signIn($signIn, true);
        }

        private function _signIn(_SignIn $signIn, bool $forced)
        {
            $userArray = null;
            if ($signIn->uid != null) {
                $userArray = $this->_getPrivateUserWithUID('passwordHash, uid, disabled', $signIn->uid);
            } elseif ($signIn->mobile != null) {
                $userArray = $this->_getPrivateUser('passwordHash, uid, disabled', 'mobile', $signIn->mobile, $signIn->type);
            } elseif ($signIn->email != null) {
                $userArray = $this->_getPrivateUser('passwordHash, uid, disabled', 'email', $signIn->email, $signIn->type);
            } else {
                throw Errors::ERROR_NO_EMIAL_OR_MOBILE_PROVIDED();
            }
            if ($userArray == null) {
                throw Errors::ERROR_USER_NOT_EXIST();
            } elseif (!$forced && !password_verify($signIn->password, $userArray['passwordHash'])) {
                throw Errors::ERROR_PASSWORD_INCORRECT();
            } elseif ($userArray['disabled'] == 1) {
                throw Errors::ERROR_USER_DISABLED();
            } else {
                return $this->_tokenSignIn($userArray['uid'], false, null);
            }
        }

        // ***********5*885*ad5sff*8f*a/8d*f/---------GET USER --------asdfa46546****asdf*a*dsf**adsf********
        public function getUser(string $uid)
        {
            return $this->_getPrivateUserWithUID('*', $uid);
        }
        public function getExtraJson(string $uid)
        {
            return $this->_getPrivateUserWithUID('extras', $uid);
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

        public function getUserType(string $uid): int
        {
            $userArr = $this->_getPrivateUserWithUID('type', $uid);
            if ($userArr != null && sizeof($userArr) > 0) {
                return $userArr[0]['type'];
            } else {
                throw Errors::D_ERROR_UNKNOWN();
            }
        }

        public function getUsersCount(): int
        {
            $query = "SELECT count(*) FROM `fast_auth_users`";
            $res = $this->db->query($query);
            if (!$res) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
            if ($row = $res->fetch_assoc()) {
                return $row['count(*)'];
            } else {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
        }
        public function getPagesCount(int $usersCount, int $usersPerPage = 20): int
        {
            return ceil($usersCount / $usersPerPage);
        }



        public function listUsers(int $page = 1, int $usersPerPage = 20, string $orderBy = 'createdAt DESC'): array
        {
            $offset = ($page - 1) * $usersPerPage;
            $query = "SELECT * FROM `fast_auth_users` ORDER BY $orderBy LIMIT $offset, $usersPerPage";
            $res = $this->db->query($query);
            if (!$res) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
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
                throw Errors::ERROR_MOBILE_ALREADY_EXISTS();
            }
            $this->_updateUser(['mobile' => $newMobile], $uid);
        }
        public function forceUpdateEmail(string $uid, string $newEmail, int $type = 0)
        {
            if ($this->_isUserExist('email', $newEmail, $type)) {
                throw Errors::ERROR_EMAIL_ALREADY_EXISTS();
            }
            $this->_updateUser(['email' => $newEmail], $uid);
        }

        public function updateMobileRequest(string $uid, string $newMobile, int $type = 0)
        {
            if ($this->_isUserExist('mobile', $newMobile, $type)) {
                throw Errors::ERROR_MOBILE_ALREADY_EXISTS();
            }
            $row = $this->_getPrivateUserWithUID('name', $uid);
            return $this->_insertTemp($uid, self::CASE_UPDATE_MOBILE, ['mobile' => $newMobile, 'name' => $row['name']], true);
        }

        public function updateEmailRequest(string $uid, string $newEmail, int $type = 0)
        {
            if ($this->_isUserExist('email', $newEmail, $type)) {
                throw Errors::ERROR_EMAIL_ALREADY_EXISTS();
            }
            $row = $this->_getPrivateUserWithUID('name', $uid);
            return $this->_insertTemp($uid, self::CASE_UPDATE_EMAIL, ['email' => $newEmail, 'name' => $row['name']], true);
        }

        // Password Update and resets
        public function resetPasswordRequestWithEmail(string $email, int $type = 0)
        {
            $row = $this->_getPrivateUser('uid, name', 'email', $email, $type);
            return $this->_insertTemp($row['uid'], self::CASE_UPDATE_PASSWORD, ['email' => $email, 'name' => $row['name']], true);
        }

        public function resetPasswordRequestWithMobile(string $mobile, int $type = 0)
        {
            $row = $this->_getPrivateUser('uid, name', 'mobile', $mobile, $type);
            return $this->_insertTemp($row['uid'], self::CASE_UPDATE_PASSWORD, ['mobile' => $mobile, 'name' => $row['name']], true);
        }

        public function updatePassword(string $passwordUpdateKey, string $newPassword)
        {
            $row = $this->_getKeyData($passwordUpdateKey, 'uid, createdAt');
            if (Utils::_isValidTimePeriod($row['createdAt'], $this->keyExpiresIn)) {
                throw Errors::ERROR_KEY_EXPIRED();
            }
            $this->_clearTable('fast_auth_temp', 'key', $passwordUpdateKey);
            return $this->_updateUser([
                'passwordHash' => password_hash($newPassword, PASSWORD_BCRYPT),
                'passwordUpdatedAt' => Utils::_getCurrentTimeForMySQL()
            ], $row['uid']);
        }

        public function updatePasswordWithCurrentPassword(string $uid, string $currentPassword, string $newPassword)
        {
            $row = $this->_getPrivateUserWithUID('passwordHash', $uid);
            if (!password_verify($currentPassword, $row['passwordHash'])) {
                throw Errors::ERROR_PASSWORD_INCORRECT();
            }
            return $this->_updateUser([
                'passwordHash' => password_hash($newPassword, PASSWORD_BCRYPT),
                'passwordUpdatedAt' => Utils::_getCurrentTimeForMySQL()
            ], $uid);
        }

        // force
        public function updateName(string $uid, string $newName)
        {
            return $this->_updateUser(['name' => $newName], $uid);
        }
        public function updateExtras(string $uid, array $extras = null)
        {
            if ($extras == null) {
                return $this->_updateUser(['extras' => null], $uid);
            }
            return $this->_updateUser(['extras' => json_encode($extras)], $uid);
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

        public function verifyToken(string $token): string
        {
            $query = "SELECT * FROM `fast_auth_tokens` WHERE `token` = '$token'";
            $res = $this->db->query($query);
            if (!$res) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$res->num_rows) {
                throw Errors::ERROR_TOKEN_INVALID();
            }
            if ($row = $res->fetch_assoc()) {
                $timeGap = Utils::_isValidTimePeriod($row['createdAt'], $row['expiresIn']);
                if (!$timeGap) {
                    throw Errors::ERROR_TOKEN_EXPIRED();
                } elseif ($row['disabled']) {
                    throw Errors::ERROR_TOKEN_DISABLED();
                } else {
                    $timeGap = $timeGap + $this->tokenExpirePeriod;
                    $q2 = "UPDATE `fast_auth_tokens` SET `expiresIn` = '$timeGap' WHERE `token` = '$token'";
                    $this->db->query($q2);
                    return $row['uid'];
                }
            } else {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
        }

        public function signOutAllDevices(string $uid, string $exceptToken = null): void
        {
            $query = "UPDATE `fast_auth_tokens` SET `disabled` = 1 WHERE `uid` = '$uid'";
            if ($exceptToken) {
                $query .= " AND `token` <> '$exceptToken'";
            }
            if (!$this->db->query($query)) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
        }

        /*------  ------- |  \        |   /\   -------  -------
        |      | |      | |   \      |   / \     |     |
        |------  \------  |    \    |   ----     |     -------  Functions:
        |       | \       |     \  |  /     \    |    |
        |      |   \      |      \| /        \   |    -------

*/

        private function _setOptions(Options $option = null): void
        {
            if ($option == null)
                $option = new Options();
            $this->OTPLength = $option->OTPLength;
            $this->OTPCharacters = $option->OTPCharacters;
            $this->keyExpiresIn = $option->keyExpiresIn;
            $this->tokenExpirePeriod = $option->tokenExpirePeriod;
            $this->decodeOTPAttempts = $option->decodeOTPAttempts;
        }

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
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
            return true;
        }

        private function _getPrivateUserWithUID(string $columns, string $uid)
        {
            $query = "SELECT $columns FROM `fast_auth_users` WHERE `uid` = '$uid'";
            $res = $this->db->query($query);
            if (!$res) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$res->num_rows) {
                throw Errors::ERROR_USER_NOT_EXIST();
            }
            if ($row = $res->fetch_assoc()) {
                return $row;
            } else {
                throw Errors::D_ERROR_UNKNOWN();
            }
        }

        private function _getPrivateUser(string $columns, string $key, string $value, int $type)
        {
            $query = "SELECT $columns FROM `fast_auth_users` WHERE `$key` = '$value' AND `type` = $type";
            $res = $this->db->query($query);
            if (!$res) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$res->num_rows) {
                throw Errors::ERROR_USER_NOT_EXIST();
            }
            if ($row = $res->fetch_assoc()) {
                return $row;
            } else {
                throw Errors::D_ERROR_UNKNOWN();
            }
        }
        private function _isUserExist(string $key, string $value, int $type)
        {
            try {
                $this->_getPrivateUser('uid', $key, $value, $type);
                return true;
            } catch (Exception $e) {
                return false;
            }
        }
        private function _isUserExistWithUID(string $uid)
        {
            try {
                $this->_getPrivateUserWithUID('uid', $uid);
                return true;
            } catch (Exception $e) {
                return false;
            }
        }


        // todo forceCreateUserWith* Function
        private function _newTempUser(_SignUp $signUp, array $params): string
        {
            if ($this->_isUserExistWithUID($signUp->uid))
                throw Errors::ERROR_USER_NOT_EXIST();

            return $this->_insertTemp($signUp->uid, self::CASE_NEW_USER, $params);
        }

        private function _insertTemp(string $uid, int $case, array $params = null, bool $checkIsUidExist = false): string
        {
            if ($checkIsUidExist && !$this->_isUserExistWithUID($uid)) { //check krna hai aur user exist nahi karta to
                throw Errors::ERROR_USER_NOT_EXIST();
            }
            $key = Utils::randomKey();
            $currentDate = Utils::_getCurrentTimeForMySQL();

            $query = '';
            if ($params != null) {
                $data = json_encode(Utils::_filterArray($params));
                $otp = $this->_generateRandomOTP();
                $otpHash = Utils::_cryptOTP($otp);
                $query = "INSERT INTO `fast_auth_temp` (`key`,`uid`,`otpHash`,`createdAt`,`case`,`data`) VALUES ('$key', '$uid', '$otpHash', '$currentDate', '$case', '$data');";
            } else {
                $query = "INSERT INTO `fast_auth_temp` (`key`,`uid`,`createdAt`,`case`) VALUES ('$key', '$uid', '$currentDate', '$case');";
            }

            if (!$this->db->query($query)) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
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
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
            if (!$res->num_rows) {
                throw Errors::ERROR_KEY_INVALID();
            }
            if ($row = $res->fetch_assoc()) {
                return $row;
            } else {
                throw Errors::D_ERROR_UNKNOWN();
            }
        }

        private function _insertUser(string $uid, array $params)
        {
            if (isset($params['mobile']) && $this->_isUserExist('mobile', $params['mobile'], $params['type'])) {
                throw Errors::ERROR_MOBILE_ALREADY_EXISTS();
            } elseif (isset($params['email']) && $this->_isUserExist('email', $params['email'], $params['type'])) {
                throw Errors::ERROR_EMAIL_ALREADY_EXISTS();
            }

            // unset($params['case']);

            $colums = "";
            $values = "";
            foreach ($params as $key => $value) {
                if ($value == null) {
                    continue;
                }
                $colums .= "`$key`,";
                if ($key === 'extras') {
                    $value = json_encode($value);
                }
                $values .= "'$value',";
            }
            $currentTime = Utils::_getCurrentTimeForMySQL();
            $query = "INSERT INTO `fast_auth_users` ($colums `uid`, `createdAt`, `passwordUpdatedAt`) VALUES 
        ($values '$uid', '$currentTime', '$currentTime');";
            if (!$this->db->query($query)) {
                throw Errors::D_ERROR_MYSQLI_QUERY();
            }
        }

        private function _tokenSignIn(string $uid, bool $isAnonymous, array $deviceJson = null)
        {
            $token = Utils::randomToken();
            $currentTime = Utils::_getCurrentTimeForMySQL();
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
                throw Errors::D_ERROR_MYSQLI_QUERY();
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
    }
}

namespace PHPFastAuth {



    class SignUpWithMobile extends _SignUp
    {
        public function __construct(string $mobile)
        {
            $this->init();
            $this->mobile = $mobile;
        }
    }

    class SignUpWithEmail extends _SignUp
    {
        public function __construct(string $email)
        {
            $this->init();
            $this->email = $email;
        }
    }

    class SignInWithMobile extends _SignIn
    {
        public function __construct(string $mobile)
        {
            $this->init();
            $this->mobile = $mobile;
        }
    }

    class SignInWithEmail extends _SignIn
    {
        public function __construct(string $email)
        {
            $this->init();
            $this->email = $email;
        }
    }
    class SignInWithUID extends _SignIn
    {
        public function __construct(string $uid)
        {
            $this->init();
            $this->uid = $uid;
        }
    }

    class _SignIn
    {
        protected function init()
        {
            $this->type = 0;
            $this->uid = null;
            $this->email = null;
            $this->mobile = null;
            $this->password = null;
        }
        public function setPassword(string $password): void
        {
            $this->password = $password;
        }
        public function setType(int $type): void
        {
            $this->type = $type;
        }
    }

    class _SignUp
    {
        protected function init()
        {
            $this->type = 0;
            $this->uid = Utils::randomUID();
            $this->email = null;
            $this->mobile = null;
            $this->name = null;
            $this->password = null;
            $this->extras = null;
        }
        public function setPassword(string $password): void
        {
            $this->password = $password;
        }
        public function setName(string $name): void
        {
            $this->name = $name;
        }
        public function setType(int $type): void
        {
            $this->type = $type;
        }
        public function setExtras(array $extras): void
        {
            $this->extras = $extras;
        }
        public function setUid(string $uid): void
        {
            $this->uid = $uid;
        }
    }

    class OTPData
    {
        public function __construct(string $otp, int $case, string $name)
        {
            $this->otp = $otp;
            $this->case = $case;
            $this->name = $name;
            $this->type = null;
            $this->mobile = null;
            $this->email = null;
        }
        public function getOTP(): string
        {
            return $this->otp;
        }
        function getCase(): int
        {
            return $this->case;
        }
        function getName(): string
        {
            return $this->name;
        }
        public function getMobile(): string
        {
            return $this->mobile;
        }
        public function getEmail(): string
        {
            return $this->email;
        }
        public function getType(): string
        {
            return $this->type;
        }
    }

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

    class Utils
    {
        static function _isValidTimePeriod(string $createdAt, int $expiresIn): int
        {
            $time = strtotime($createdAt) + $expiresIn;
            $currentTime = time();
            if ($time > $currentTime) {
                return $time - $currentTime;
            }
            return 0;
        }

        static function _cryptOTP(string $otp): string
        {
            return openssl_encrypt($otp, "AES-128-ECB", "__^!@XQ@z#$&*^%%Y&$&*^__");
        }

        static function _decryptOTP(string $otpHash): string
        {
            return openssl_decrypt($otpHash, "AES-128-ECB", "__^!@XQ@z#$&*^%%Y&$&*^__");
        }

        static function _getCurrentTimeForMySQL(): string
        {
            return date('Y-m-d H:i:s', time());
        }

        static function _filterArray($array): array
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

        private const UID_LENGTH = 16;
        private const TOKEN_LENGTH = 39;
        private const KEY_LENGTH = 32;


        static function randomUID(): string
        {
            return self::_randomStr(self::UID_LENGTH);
        }
        static function randomKey(): string
        {
            return self::_randomStr(self::KEY_LENGTH);
        }
        static function randomToken(): string
        {
            return self::_randomStr(self::TOKEN_LENGTH);
        }
        private static function _randomStr(int $length): string
        {
            return bin2hex(openssl_random_pseudo_bytes($length));
        }
    }


    class Errors
    {
        public const ERROR_CODE = 30;
        public const ERROR_NO_EMIAL_OR_MOBILE_PROVIDED_CODE = 46;
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
        public static function ERROR_NO_EMIAL_OR_MOBILE_PROVIDED()
        {
            return new \Exception('No email or moblie is provided', self::ERROR_NO_EMIAL_OR_MOBILE_PROVIDED_CODE);
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
