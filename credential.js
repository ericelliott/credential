/**
 * credential
 *
 * Fortify your user's passwords against rainbow table,
 * brute force, and variable hash time attacks using Node's
 * built in crypto functions.
 *
 * Employs cryptographically secure, password unique salts to
 * prevent rainbow table attacks.
 *
 * Key stretching is used to make brute force attacks
 * impractical.
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
   * @param  {[type]}   password
   * @param  {[type]}   salt
   * @param  {Function} callback err, buffer
   */
  pbkdf2 = function pbkdf2(password, salt, iterations, keylength, callback) {
    crypto.pbkdf2(password, salt,
      iterations, keylength, function (err, hash) {
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
   * @param  {Function} callback [description]
   * @return {[type]}            [description]
   */
  createSalt = function createSalt(keylength, callback) {
    crypto.randomBytes(keylength, function (err, buff) {
      if (err) {
        return callback(err);
      }
      callback(null, buff.toString('base64'));
    });
  },

  /**
   * toHash(password, callback)
   *
   * Takes a new password and creates a unique salt and hash
   * combination in the form `salt$hash`, suitable for storing
   * in a single text field.
   *
   * @param  {[type]}   password
   * @param  {Function} callback
   */
  toHash = function toHash(password,
      callback) {
    var hashMethod = this.hashMethod,
      keylength = this.keylength,
      iterations = this.iterations;

    // Create the salt
    createSalt(keylength, function (err, salt) {
      if (err) {
        return callback(err);
      }

      // Then create the hash
      hashMethods[hashMethod](password, salt,
          iterations, keylength,
          function (err, hash) {

        if (err) {
          return callback(err);
        }

        callback(null, JSON.stringify({
          salt: salt,
          hash: hash,
          hashMethod: hashMethod,
          iterations: iterations,
          keylength: keylength
        }));

      });
    }.bind(this));
  },

  /**
   * constantEquals(x, y)
   *
   * Compare two equal-length hashes, x and y with a
   * constant-time algorithm to prevent attacks based on
   * timing statistics.
   */
  constantEquals = function constantEquals(x, y) {
    var result = true,
      length = y.length,
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
    var storedHash = parseHash(hash);

    if (!hashMethods[storedHash.hashMethod]) {
      return callback(new Error('Couldn\'t parse stored ' +
        'hash.'));
    }

    hashMethods[storedHash.hashMethod](input, storedHash.salt, storedHash.iterations,
        storedHash.keylength, function (err, newHash) {

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
   * Alter defaults for `keylength` or `iterations`.
   * Warning: Decreasing these values can make your password
   * database less secure.
   *
   * @param  {Object} options Options object.
   * @param  {Number} options.keylength
   * @param  {Number} options.iterations
   * @return {Object}         credential object
   */
  configure = function configure(options) {
    mixIn(this, this.defaults, options);
    return this;
  },

  defaults = {
    keylength: 66,
    iterations: 80000,
    hashMethod: 'pbkdf2'
  };

module.exports = mixIn({}, defaults, {
  hash: toHash,
  verify: verify,
  configure: configure
});
