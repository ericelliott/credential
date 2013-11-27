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

'use strict';
var crypto = require('crypto'),
  mixIn = require('mout/object/mixIn'),

  /**
   * pdkdf(password, salt, workUnits, workKey,
   *   keyLength, callback) callback(err, hash)
   *
   * A standard to employ hashing and key stretching to
   * prevent rainbow table and brute-force attacks, even
   * if an attacker steals your password database.
   *
   * This function is a thin wrapper around Node's built-in
   * crypto.pbkdf2().
   *
   * See Internet Engineering Task Force RFC 2898
   * 
   * @param  {String}   password
   * @param  {String}   salt
   * @param  {Number}   workUnits
   * @param  {Number}   workKey
   * @param  {Number}   keyLength
   * @param  {Function} callback
   * @return {undefined}
   */
  pbkdf2 = function pbkdf2(password, salt, workUnits,
      workKey, keyLength, callback) {
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
   * createSalt(keylength, callback) callback(err, salt)
   *
   * Generates a cryptographically secure random string for
   * use as a password salt using Node's built-in
   * crypto.randomBytes().
   *
   * @param  {Number} keyLength
   * @param  {Function} callback 
   * @return {undefined}
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
   * toHash(password, callback) callback(err, hash)
   *
   * Takes a new password and creates a unique hash. Passes
   * a JSON encoded object to the callback.
   *
   * @param  {[type]}   password
   * @param  {Function} callback
   */
  /**
   * callback
   * @param  {Error}  Error Error or null
   * @param  {String} hashObject JSON string
   * @param  {String} hashObject.hash
   * @param  {String} hashObject.salt
   * @param  {Number} hashObject.keyLength
   * @param  {String} hashObject.hashMethod
   * @param  {Number} hashObject.workUnits
   * @return {undefined}
   */
  toHash = function toHash(password,
      callback) {
    var hashMethod = this.hashMethod,
      keyLength = this.keyLength,
      workUnits = this.workUnits,
      workKey = this.workKey;

    if (typeof (password) !== 'string' || password.length === 0) {
      return callback(new Error('Password must be a ' +
        ' non-empty string.'));
    }

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
   * 
   * @param  {String} x
   * @param  {String} y
   * @return {Boolean}
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
   * verify(hash, input, callback) callback(err, isValid)
   *
   * Takes a stored hash, password input from the user,
   * and a callback, and determines whether or not the
   * user's input matches the stored password.
   *
   * @param  {String}   hash stored JSON object
   * @param  {String}   input user's password input
   * @param  {Function} callback(err, isValid)
   */
  verify = function verify(hash, input, callback) {
    var storedHash = parseHash(hash),
      workKey = this.workKey;

    if (!hashMethods[storedHash.hashMethod]) {
      return callback(new Error('Couldn\'t parse stored ' +
        'hash.'));
    }
    else if (typeof (input) !== 'string' || input.length === 0) {
        return callback(new Error('Input password must ' +
          ' be a non-empty string.'));
    }

    hashMethods[storedHash.hashMethod](input, storedHash.salt,
        storedHash.workUnits, workKey, storedHash.keyLength,
        function (err, newHash) {

      if (err) {
        return callback(err);
      }
      callback(null, constantEquals(newHash, storedHash.hash));
    });
  },

  /**
   * configure(options)
   *
   * Alter settings or set your secret `workKey`. `Workkey`
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
   * @return {Object} credential object
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
