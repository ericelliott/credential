/**
 * credential
 *
 * Easy password hashing and verification in Node.
 * Protects against brute force, rainbow tables, and
 * timing attacks.
 *
 * Cryptographically secure per-password salts prevent
 * rainbow table attacks.
 *
 * Variable work unit key stretching prevents brute force.
 *
 * Constant time verification prevents hang man timing
 * attacks.
 *
 * Created by Eric Elliott for the book,
 * "Programming JavaScript Applications" (O'Reilly)
 *
 * MIT license http://opensource.org/licenses/MIT
 */

var crypto = require('crypto'),
  mixIn = require('mout/object/mixIn'),
  pick = require('mout/object/pick'),

  /**
   * pbkdf2(password, salt, callback)
   *
   * A standard to employ hashing and key stretching to
   * prevent rainbow table and brute-force attacks, even
   * if an attacker steals your password database.
   *
   * This function is a thin wrapper around Node's built-in
   * crypto.pbkdf2().
   *
   * Internet Engineering Task Force's RFC 2898
   *
   * @param  {[type]}   password
   * @param  {[type]}   salt
   * @param  {Function} callback err, buffer
   */
  pbkdf2 = function pbkdf2(password, salt, workUnits, workKey, keyLength, callback) {
    var baseline = 1000,
      iterations = (baseline + workKey) * workUnits;

    crypto.pbkdf2(password, salt,
      iterations, keyLength, function (err, hash) {
        if (err) {
          return callback(err);
        }
        callback(null, new Buffer(hash).toString('base64'));
      });
  },

  hashMethods = {
    pbkdf2: pbkdf2
  },

  /**
   * createSalt(callback)
   *
   * Generates a cryptographically secure random string for
   * use as a password salt using Node's built-in
   * crypto.randomBytes().
   *
   * @param  {Numbre} keyLength  Number of bytes.
   * @param  {Function} callback [description]
   * @return {[type]}            [description]
   */
  createSalt = function createSalt(keyLength, callback) {
    crypto.randomBytes(keyLength, function (err, buff) {
      if (err) {
        return callback(err);
      }
      callback(null, buff.toString('base64'));
    });
  },

  /**
   * toHash(password, callback)
   *
   * Takes a new password and creates a unique hash. Passes
   * a JSON encoded object to the callback.
   *
   * @param  {[type]}   password
   * @param  {Function} callback
   */
  /**
   * callback
   * @param  {Error}   Error     Error or null
   * @param  {JSON} hashObject
   * @param  {String} hashObject.hash
   * @param  {String} hashObject.salt
   * @param  {Number} hashObject.keyLength Bytes in hash
   * @param  {String} hashObject.hashMethod
   * @param  {Number} hashObject.workUnits
   */
  toHash = function toHash(password,
      callback) {
    var hashMethod = this.hashMethod,
      keyLength = this.keyLength,
      workUnits = this.workUnits,
      workKey = this.workKey;

    // Create the salt
    createSalt(keyLength, function (err, salt) {
      if (err) {
        return callback(err);
      }

      // Then create the hash
      hashMethods[hashMethod](password, salt,
          workUnits, workKey, keyLength,
          function (err, hash) {

        if (err) {
          return callback(err);
        }

        callback(null, JSON.stringify({
          hash: hash,
          salt: salt,
          keyLength: keyLength,
          hashMethod: hashMethod,
          workUnits: workUnits
        }));

      });
    }.bind(this));
  },

  /**
   * constantEquals(x, y)
   *
   * Compare two strings, x and y with a constant-time
   * algorithm to prevent attacks based on timing statistics.
   */
  constantEquals = function constantEquals(x, y) {
    var result = true,
      length = (x.length > y.length) ? x.length : y.length,
      i;

    for (i=0; i<length; i++) {
      if (x.charCodeAt(i) !== y.charCodeAt(i)) {
        result = false;
      }
    }
    return result;
  },

  parseHash = function parseHash(encodedHash) {
    try {
      return JSON.parse(encodedHash);
    } catch (err) {
      return err;
    }
  },

  /**
   * verify(hash, input, callback)
   *
   * Takes a stored hash, password input from the user,
   * and a callback, and determines whether or not the
   * user's input matches the stored password.
   *
   * @param  {[type]}   hash     stored password hash
   * @param  {[type]}   input    user's password input
   * @param  {Function} callback callback(err, isValid)
   */
  verify = function verify(hash, input, callback) {
    var storedHash = parseHash(hash),
      workKey = this.workKey;

    if (!hashMethods[storedHash.hashMethod]) {
      return callback(new Error('Couldn\'t parse stored ' +
        'hash.'));
    }

    hashMethods[storedHash.hashMethod](input, storedHash.salt,
        storedHash.workUnits, workKey, storedHash.keyLength,
        function (err, newHash) {

      var result;
      if (err) {
        return callback(err);
      }
      callback(null, constantEquals(newHash, storedHash.hash));
    });
  },

  /**
   * configure(options)
   *
   * Alter settings or set your secret workKey. Workkey
   * is a secret value between one and 999, required to verify
   * passwords. This secret makes it harder to brute force
   * passwords from a stolen database by obscuring the number
   * of iterations required to test passwords.
   *
   * Warning: Decreasing `keyLength` or `work units`
   * can make your password database less secure.
   *
   * @param  {Object} options Options object.
   * @param  {Number} options.keyLength
   * @param  {Number} options.workUnits
   * @param  {Number} options.workKey secret
   * @return {Object}         credential object
   */
  configure = function configure(options) {
    mixIn(this, this.defaults, options);
    return this;
  },

  defaults = {
    keyLength: 66,
    workUnits: 60,
    workKey: parseInt(process.env.credential_key, 10) || 388,
    hashMethod: 'pbkdf2'
  };

module.exports = mixIn({}, defaults, {
  hash: toHash,
  verify: verify,
  configure: configure
});
